"""Blocklist matching and list-file parsing — docs/FILTER-SPEC.md.

A direct port of the shared Sphinx core (the Android edition's
``core/Blocklist.kt`` + ``core/FilterLists.kt``, via the Windows
edition's Python port), so every edition runs the same brain:

- Names compare case-insensitively, without a trailing dot.
- A name is blocked when it equals a blocklist entry or is a
  subdomain of one. An entry never blocks its own parent or siblings.
- The allowlist uses the same walk and wins over the blocklist
  (FILTER-SPEC matching rule 5).

Pure Python — no platform APIs — so the whole core is testable
anywhere.
"""
from __future__ import annotations

import re
from typing import Collection, Iterable, Optional

_DOMAIN_SHAPE = re.compile(
    r"^[a-z0-9]([a-z0-9-]*[a-z0-9])?(\.[a-z0-9]([a-z0-9-]*[a-z0-9])?)*$"
)
_IPV4_SHAPE = re.compile(r"^\d+\.\d+\.\d+\.\d+$")
_WHITESPACE = re.compile(r"\s+")

#: Names that appear in hosts files as local-machine plumbing, never
#: as blockable domains. A list line naming one of these is
#: infrastructure, not an ad server, and is skipped.
RESERVED_NAMES = frozenset(
    {
        "localhost",
        "localhost.localdomain",
        "local",
        "broadcasthost",
        "ip6-localhost",
        "ip6-loopback",
        "ip6-localnet",
        "ip6-mcastprefix",
        "ip6-allnodes",
        "ip6-allrouters",
        "ip6-allhosts",
    }
)


def normalize(raw: Optional[str]) -> Optional[str]:
    """Canonical form of a domain name, or None if it can't be one.

    Accepts a bare name ("ads.example.com"), a wildcard form
    ("*.example.com" — same meaning here), any case, trailing dots.
    An IP literal is never a domain entry and is rejected.
    """
    if raw is None:
        return None
    name = raw.strip().lower()
    if name.startswith("*."):
        name = name[2:]
    name = name.rstrip(".")
    if not name:
        return None
    # Labels of letters/digits/hyphens, dot-separated — anything else
    # is a junk line from a list file, not a domain.
    if not _DOMAIN_SHAPE.match(name):
        return None
    if _IPV4_SHAPE.match(name):
        return None
    return name


def normalize_entry(raw: Optional[str]) -> Optional[str]:
    """Canonical form of a single list *entry*, or None if it may not
    be one: everything :func:`normalize` requires, plus the parsing
    safety rails — no single-label entries (a one-word entry would
    block a whole top-level domain) and no reserved local names.

    The list parser uses this, and so does every other path that
    accepts an entry (an allowlist editor, a custom-entry field), so
    an entry that would be dropped at load time is refused at entry
    time instead of silently doing nothing.
    """
    name = normalize(raw)
    if name is None:
        return None
    if "." not in name:
        return None
    if name in RESERVED_NAMES:
        return None
    return name


def _is_ip_literal(token: str) -> bool:
    """A hosts-file address token: dotted-quad IPv4, or any IPv6 form."""
    return bool(_IPV4_SHAPE.match(token)) or ":" in token


def _add_entry(token: str, out: set) -> None:
    name = normalize_entry(token)
    if name is not None:
        out.add(name)


def _parse_line(line: str, out: set) -> None:
    text = line
    hash_at = text.find("#")
    if hash_at >= 0:
        text = text[:hash_at]
    text = text.strip()
    if not text:
        return
    tokens = _WHITESPACE.split(text)
    if len(tokens) >= 2 and _is_ip_literal(tokens[0]):
        # Hosts-file line: every token after the address is a name
        # for that address.
        for token in tokens[1:]:
            _add_entry(token, out)
    else:
        _add_entry(tokens[0], out)


def parse_entries(lines: Iterable[str]) -> set:
    """The normalized entry set a list file parses to.

    Supported shapes (FILTER-SPEC, "List files"):
      - "ads.example.com"           (plain, one per line)
      - "*.ads.example.com"         (wildcard — same meaning)
      - "0.0.0.0 ads.example.com"   (hosts file: an IP literal, then
        one or more names; IPv6 literals work the same way)
      - "# comment", blank lines, and trailing "# ..." notes on a
        line are ignored.

    Safety rails while parsing: reserved local names are skipped;
    single-label entries are skipped; anything that doesn't
    normalize to a domain is skipped.
    """
    entries: set = set()
    for line in lines:
        _parse_line(line, entries)
    return entries


class Blocklist:
    """A set of normalized blocklist entries with subdomain matching."""

    def __init__(self, entries: Collection[str]):
        # The normalized entries, as a set. Note: construction
        # normalizes but does not apply the parsing rails — the rails
        # are a *parsing* rule, and every production construction
        # path goes through the parser or unions of parsed sets
        # (the same arrangement as the other editions).
        self.domains = {n for n in (normalize(e) for e in entries) if n}

    def __len__(self) -> int:
        return len(self.domains)

    @property
    def size(self) -> int:
        return len(self.domains)

    def is_blocked(self, name: str) -> bool:
        candidate = normalize(name)
        if candidate is None:
            return False
        while True:
            if candidate in self.domains:
                return True
            dot = candidate.find(".")
            if dot < 0:
                return False
            candidate = candidate[dot + 1 :]
            if not candidate:
                return False

    @classmethod
    def from_lines(cls, lines: Iterable[str]) -> "Blocklist":
        return cls(parse_entries(lines))


class Allowlist:
    """Names the user has said never to block.

    Matching uses the exact same walk as the blocklist (a name is
    covered when it, or any parent of it, is listed) — FILTER-SPEC
    matching rule 5.
    """

    def __init__(self, entries: Collection[str]):
        self._matcher = Blocklist(entries)

    def __len__(self) -> int:
        return len(self._matcher)

    @property
    def size(self) -> int:
        return self._matcher.size

    def covers(self, name: str) -> bool:
        return self._matcher.is_blocked(name)

    @classmethod
    def from_lines(cls, lines: Iterable[str]) -> "Allowlist":
        return cls(parse_entries(lines))


class FilterLists:
    """The pair of lists a filter actually runs with, and the one
    decision it makes per query (FILTER-SPEC):

    - Allowlist wins: a covered name is never blocked, even when a
      blocklist entry covers it too.
    - Otherwise the blocklist decides.
    """

    def __init__(self, blocklist: Blocklist, allowlist: Allowlist):
        self.blocklist = blocklist
        self.allowlist = allowlist

    def is_blocked(self, name: str) -> bool:
        if self.allowlist.covers(name):
            return False
        return self.blocklist.is_blocked(name)
