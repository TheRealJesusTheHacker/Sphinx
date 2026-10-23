"""OpenVPN config sanitization — security-critical (Phase 2).

An OpenVPN config is text that the ``openvpn`` client would act on
as root. Configs from files — and especially from the public VPN
Gate feed — are strangers' text. Before any connect, Sphinx strips
every directive that could execute code, persist, manage the
client from elsewhere, or write files, and the sanitized result is
the only text that ever runs. Nothing is edited silently: the
sanitizer returns the list of what it removed, and the guard names
those removals in its status/verbose output.

Sphinx runs the client with its own controlled flags instead
(``--script-security`` is never passed; the posture is achieved by
the *absence* of script hooks — no ``up``/``down``/plugin lines
survive to be run). If Sphinx ever needs its own up/down hook, it
will be a Sphinx-shipped file named on Sphinx's command line,
never a line taken from a config.
"""
from __future__ import annotations

from dataclasses import dataclass, field
from typing import List, Tuple

#: Directives removed unconditionally (first token of the line).
#: Each can execute code, hand control elsewhere, change the
#: process's filesystem view, daemonize/persist, or write files.
STRIPPED_DIRECTIVES = frozenset({
    "up", "down", "route-up", "route-pre-down",
    "plugin",
    "script-security",
    "management", "management-client", "management-query-passwords",
    "iproute",
    "tls-verify",
    "cd", "chroot",
    "daemon",
    "writepid", "pidfile",
    "status",
    "log", "log-append", "syslog",
    "client-connect", "client-disconnect", "learn-address",
    "auth-gen-token",  # server-side token issuance has no client meaning; a config carrying it is not a client config
    "setenv", "setenv-opt",  # environment handed to (absent) scripts / child processes
})

#: Directives removed only in a dangerous form.
#: ``auth-user-pass`` with a file argument would read credentials
#: from a path the config chooses; the bare form (prompt) is kept.
_CONDITIONAL = {"auth-user-pass"}


@dataclass
class SanitizedConfig:
    text: str
    removed: List[str] = field(default_factory=list)  # human-readable removal notes, in order


def _first_token(line: str) -> Tuple[str, str]:
    stripped = line.strip()
    if not stripped or stripped.startswith(("#", ";")):
        return "", stripped
    parts = stripped.split(None, 1)
    return parts[0].lower(), (parts[1] if len(parts) > 1 else "")


def sanitize_openvpn_config(text: str) -> SanitizedConfig:
    """Return the sanitized config and what was removed.

    Inline blocks (``<ca>`` … ``</ca>`` etc.) pass through
    untouched — their contents are data (certificates/keys), not
    directives. A directive line inside such a block is not a
    directive and is not treated as one.
    """
    out: List[str] = []
    removed: List[str] = []
    in_block = False
    for line in text.splitlines():
        stripped = line.strip()
        if in_block:
            out.append(line)
            if stripped.startswith("</") and stripped.endswith(">"):
                in_block = False
            continue
        if stripped.startswith("<") and stripped.endswith(">") and not stripped.startswith("</"):
            in_block = True
            out.append(line)
            continue
        token, rest = _first_token(line)
        if not token:
            out.append(line)
            continue
        if token in STRIPPED_DIRECTIVES:
            removed.append(f"{token}" + (f" {rest.split()[0]}" if rest and token in ("plugin", "management") else ""))
            continue
        if token == "auth-user-pass" and rest.strip():
            removed.append("auth-user-pass (with a file argument)")
            continue
        out.append(line)
    return SanitizedConfig(text="\n".join(out) + ("\n" if out else ""), removed=removed)


#: Pushed-DNS rejection lines Sphinx appends to every sanitized
#: OpenVPN session config (the DNS design, Phase 2): servers the
#: remote pushes are ignored, so the resolver Sphinx already
#: manages — the profile's/Sphinx's — stands, unchanged and exactly
#: restorable because it never moved.
PULL_FILTER_LINES = (
    'pull-filter ignore "dhcp-option DNS"',
    'pull-filter ignore "dhcp-option DOMAIN"',
    'pull-filter ignore "dhcp-option DOMAIN-SEARCH"',
)


def render_session_config(text: str) -> SanitizedConfig:
    """Sanitize + append Sphinx's own pull-filter DNS lines."""
    result = sanitize_openvpn_config(text)
    body = result.text
    if body and not body.endswith("\n"):
        body += "\n"
    body += "\n".join(PULL_FILTER_LINES) + "\n"
    return SanitizedConfig(text=body, removed=list(result.removed))
