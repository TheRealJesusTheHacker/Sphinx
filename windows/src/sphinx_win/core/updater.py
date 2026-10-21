"""Downloads fresh copies of the configured blocklists and swaps
them in — carefully (FILTER-SPEC, "List updates"). A port of the
Android edition's ``lists/ListUpdater.kt``:

 1. Every source is fetched over HTTPS and fully parsed.
 2. A source whose download fails, or whose contents don't parse to
    a sane list, keeps its previous downloaded copy. It never
    replaces a good list with a bad download.
 3. The would-be new blocklist (fresh downloads plus kept copies)
    must pass the sanity gate as a whole before anything on disk
    changes. Only then are the staged files written (each by
    temp-file + rename) and the update recorded.

If the whole update can't pass the gate, nothing is written and the
working lists are exactly what they were. Updates happen only when
the user asks — nothing here ever runs on a schedule.
"""
from __future__ import annotations

import urllib.error
import urllib.request
from dataclasses import dataclass, field
from typing import List, Optional

from .blocklist import Blocklist
from .store import Store
from .validation import (
    ListSource,
    is_acceptable,
    is_acceptable_url,
    parse_and_validate,
    redirect_target,
)

CONNECT_TIMEOUT_S = 15.0
READ_TIMEOUT_S = 30.0
MAX_LIST_BYTES = 32 * 1024 * 1024
MAX_REDIRECTS = 5
REDIRECT_CODES = frozenset({301, 302, 303, 307, 308})
USER_AGENT = "Sphinx/0.1 (Windows blocklist update)"


@dataclass(frozen=True)
class SourceOutcome:
    source: ListSource
    refreshed: bool
    domains: int
    note: Optional[str]


@dataclass(frozen=True)
class UpdateResult:
    success: bool
    total_domains: int
    outcomes: List[SourceOutcome] = field(default_factory=list)


class _NoRedirect(urllib.request.HTTPRedirectHandler):
    """Refuse urllib's automatic redirects — editions follow them by
    hand so every hop can be vetted (see redirect_target)."""

    def redirect_request(self, req, fp, code, msg, headers, newurl):
        return None


_OPENER = urllib.request.build_opener(_NoRedirect)


def download(url: str, opener=None) -> Optional[bytes]:
    """Fetch ``url`` over HTTPS; None on any failure or an oversized
    body. Redirects are followed by hand, at most MAX_REDIRECTS, and
    every hop is checked with redirect_target: a download that starts
    on HTTPS must stay on HTTPS."""
    if not is_acceptable_url(url):
        return None
    opener = opener or _OPENER
    current = url
    hops = 0
    while True:
        request = urllib.request.Request(
            current, headers={"User-Agent": USER_AGENT}
        )
        try:
            with opener.open(request, timeout=READ_TIMEOUT_S) as response:
                body = response.read(MAX_LIST_BYTES + 1)
                if len(body) > MAX_LIST_BYTES:
                    return None
                return body
        except urllib.error.HTTPError as e:
            if e.code in REDIRECT_CODES and hops < MAX_REDIRECTS:
                target = redirect_target(current, e.headers.get("Location"))
                if target is None:
                    return None
                current = target
                hops += 1
                continue
            return None
        except Exception:
            return None


class ListUpdater:
    def __init__(self, store: Store, download_fn=download):
        self._store = store
        self._download = download_fn

    def update_all(self, now_ms: int) -> UpdateResult:
        outcomes: List[SourceOutcome] = []
        staged_bytes: dict = {}
        union: set = set()

        for source in self._store.sources():
            raw = self._download(source.url)
            parsed = (
                parse_and_validate(raw.decode("utf-8", errors="replace").splitlines())
                if raw is not None
                else None
            )
            if raw is None:
                kept = self._keep_existing(source, union)
                outcomes.append(
                    SourceOutcome(source, False, kept,
                                  "download failed — kept the previous copy")
                )
            elif parsed is None:
                kept = self._keep_existing(source, union)
                outcomes.append(
                    SourceOutcome(source, False, kept,
                                  "download didn't parse as a blocklist — "
                                  "kept the previous copy")
                )
            else:
                staged_bytes[source] = raw
                union.update(parsed.domains)
                outcomes.append(SourceOutcome(source, True, parsed.size, None))

        combined = Blocklist(union)
        if not is_acceptable(combined):
            # The gate: nothing was written above, so the working
            # lists are untouched.
            return UpdateResult(False, 0, outcomes)

        if not staged_bytes:
            # Every source failed and the gate passed only on copies
            # already on disk. Nothing was downloaded, so this is a
            # failed update — and a failed update changes nothing,
            # including the recorded last-updated time (Phase 2 audit
            # finding on the Android edition, fixed there and here).
            return UpdateResult(False, 0, outcomes)

        for source, raw in staged_bytes.items():
            self._store.write_downloaded(source, raw)
        self._store.record_update(combined.size, now_ms)
        return UpdateResult(True, combined.size, outcomes)

    def _keep_existing(self, source: ListSource, union: set) -> int:
        """Add ``source``'s previously downloaded list, if any, to
        ``union``; returns its domain count."""
        f = self._store.saved_file(source)
        if f is None:
            return 0
        parsed = parse_and_validate(
            f.read_text(encoding="utf-8", errors="replace").splitlines()
        )
        if parsed is None:
            return 0
        union.update(parsed.domains)
        return parsed.size
