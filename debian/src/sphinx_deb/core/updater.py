"""Downloads fresh copies of the configured blocklists and swaps
them in — carefully (FILTER-SPEC, "List updates"). The download
half ports the Android edition's ``lists/ListUpdater.kt`` by way
of the fleet's Python cores:

 1. Every source is fetched over HTTPS only, with redirects
    followed by hand so every hop is vetted (a downgrade to plain
    HTTP fails the download).
 2. Every download is fully parsed and must pass the sanity gate
    on its own; the merged set — unique domains across all
    sources — must pass the same gate again.
 3. Only then does anything on disk change: each staged file is
    written by temp-file + rename, and the update is recorded.

Failure is all-or-nothing, stated as plainly as it is kept: if
*any* source fails — unreachable, unparseable, too small — the
whole update has failed. Nothing is swapped, no source's previous
copy is replaced, and the recorded last-updated time does not
move. (Every source keeping its previous copy is the spec's rule;
this edition takes it at full strength rather than applying a
half-fresh set and calling it an update.) Updates happen only
when the user asks — `sphinx update`, by hand. Nothing here ever
runs on a schedule: no timers, no cron, no background fetching.
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

# urllib applies one timeout to the connect and the reads alike;
# there is no separate connect timeout to promise.
READ_TIMEOUT_S = 30.0
MAX_LIST_BYTES = 32 * 1024 * 1024
MAX_REDIRECTS = 5
REDIRECT_CODES = frozenset({301, 302, 303, 307, 308})
USER_AGENT = "Sphinx (Debian blocklist update)"


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
    on HTTPS must stay on HTTPS, on whatever host each hop lands."""
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
        failed = False

        for source in self._store.sources():
            raw = self._download(source.url)
            parsed = (
                parse_and_validate(raw.decode("utf-8", errors="replace").splitlines())
                if raw is not None
                else None
            )
            if raw is None:
                failed = True
                outcomes.append(
                    SourceOutcome(
                        source, False, 0, "could not be downloaded"
                    )
                )
            elif parsed is None:
                failed = True
                outcomes.append(
                    SourceOutcome(
                        source,
                        False,
                        0,
                        "did not parse as a blocklist (a real list "
                        "holds at least 1,000 domains)",
                    )
                )
            else:
                staged_bytes[source] = raw
                union.update(parsed.domains)
                outcomes.append(SourceOutcome(source, True, parsed.size, None))

        if failed:
            # All-or-nothing: nothing was written above, the previous
            # copies are exactly where they were, and the recorded
            # last-updated time does not move for a failed update.
            return UpdateResult(False, 0, outcomes)

        combined = Blocklist(union)
        if not is_acceptable(combined):
            # The merged-set gate (unique domains across sources) —
            # with every source individually gated this should be
            # unreachable, but the gate is the gate: nothing swaps.
            return UpdateResult(False, 0, outcomes)

        for source, raw in staged_bytes.items():
            self._store.write_downloaded(source, raw)
        self._store.record_update(combined.size, now_ms)
        return UpdateResult(True, combined.size, outcomes)
