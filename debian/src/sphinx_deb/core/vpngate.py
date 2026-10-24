"""VPN Gate public-nodes directory (Phase 2, TUNNEL-SPEC).

Pure parsing + cache bookkeeping for the VPN Gate feed
(https://www.vpngate.net/api/iphone/). Fetching itself is done by
the caller (the CLI) with an injectable fetcher, so tests never
touch the live feed. Nothing is bundled: there is no offline list.

The disclosure below is normative — it rides at the point of use,
in ``public list`` output and again before ``public connect``.
"""
from __future__ import annotations

import base64
import binascii
import csv
import io
import json
import time
import urllib.request
from dataclasses import dataclass, field
from pathlib import Path
from typing import Callable, List, Optional, Tuple

FEED_URL = "https://www.vpngate.net/api/iphone/"
MAX_FEED_BYTES = 8 * 1024 * 1024  # the real feed is a few MB; cap runaway responses
FETCH_TIMEOUT_S = 15
CACHE_FILE_NAME = "vpngate-cache.json"

DISCLOSURE = (
    "These are strangers' machines, volunteered to a research "
    "project (VPN Gate, University of Tsukuba). The operator can "
    "see your traffic. VPN Gate states its servers keep "
    "connection logs — your real address, the times, the server "
    "you used — for three months or more. Fine for appearing to "
    "be somewhere else; not for anything sensitive."
)

EMPTY_STATE = (
    "Couldn't fetch the public server list — check your "
    "connection. Nothing is bundled; there is no offline list."
)


@dataclass
class PublicRow:
    hostname: str = ""
    ip: str = ""
    country_long: str = ""
    country_short: str = ""
    score: str = ""
    ping: str = ""
    config_b64: str = ""

    @property
    def label(self) -> str:
        return f"Public volunteer server — {self.country_long} ({self.hostname})"

    def config_text(self) -> str:
        try:
            raw = base64.b64decode(self.config_b64.encode("ascii"), validate=True)
        except (binascii.Error, ValueError, UnicodeEncodeError) as exc:
            raise ValueError(f"the row's OpenVPN config is not valid base64: {exc}") from exc
        return raw.decode("utf-8", errors="strict")


def parse_feed(text: str) -> List[PublicRow]:
    """Parse the feed's CSV: comment lines start with ``*``, the
    column header is the line starting with ``#``, data rows follow
    until a ``*`` terminator. Rows whose config does not decode are
    skipped (a stranger's malformed row must not break the list)."""
    lines = [ln for ln in text.splitlines() if ln.strip()]
    header: Optional[List[str]] = None
    rows: List[PublicRow] = []
    data_lines: List[str] = []
    for line in lines:
        if line.startswith("*"):
            if header is not None:
                break
            continue
        if line.startswith("#"):
            header = [c.strip() for c in line[1:].split(",")]
            continue
        if header is not None:
            data_lines.append(line)
    if header is None:
        return []
    idx = {name: i for i, name in enumerate(header)}

    def cell(parts: List[str], name: str) -> str:
        i = idx.get(name)
        return parts[i].strip() if i is not None and i < len(parts) else ""

    for record in csv.reader(io.StringIO("\n".join(data_lines))):
        if not record or not any(c.strip() for c in record):
            continue
        row = PublicRow(
            hostname=cell(record, "HostName"),
            ip=cell(record, "IP"),
            country_long=cell(record, "CountryLong"),
            country_short=cell(record, "CountryShort"),
            score=cell(record, "Score"),
            ping=cell(record, "Ping"),
            config_b64=cell(record, "OpenVPN_ConfigData_Base64"),
        )
        if not row.config_b64:
            continue
        try:
            row.config_text()
        except (ValueError, UnicodeDecodeError):
            continue
        rows.append(row)
    return rows


# --- cache ---------------------------------------------------------


@dataclass
class CachedFeed:
    rows: List[PublicRow]
    fetched_at_ms: int

    def age_hours(self, now_ms: Optional[int] = None) -> float:
        now = int(time.time() * 1000) if now_ms is None else now_ms
        return max(0.0, (now - self.fetched_at_ms) / 3_600_000.0)

    def age_label(self, now_ms: Optional[int] = None) -> str:
        hours = self.age_hours(now_ms)
        if hours < 1:
            return "list from less than an hour ago — the live list couldn't be fetched"
        rounded_val = round(hours, 1)
        rounded = int(rounded_val) if rounded_val == int(rounded_val) else rounded_val
        unit = "hour" if rounded == 1 else "hours"
        return f"list from {rounded} {unit} ago — the live list couldn't be fetched"


def cache_path(state_dir: Path) -> Path:
    return Path(state_dir) / CACHE_FILE_NAME


def save_cache(state_dir: Path, rows: List[PublicRow], fetched_at_ms: Optional[int] = None) -> None:
    when = int(time.time() * 1000) if fetched_at_ms is None else fetched_at_ms
    payload = {
        "fetched_at_ms": when,
        "rows": [
            {
                "hostname": r.hostname, "ip": r.ip,
                "country_long": r.country_long, "country_short": r.country_short,
                "score": r.score, "ping": r.ping, "config_b64": r.config_b64,
            }
            for r in rows
        ],
    }
    path = cache_path(state_dir)
    path.parent.mkdir(parents=True, exist_ok=True)
    tmp = path.with_name(path.name + ".tmp")
    tmp.write_text(json.dumps(payload), encoding="utf-8")
    tmp.replace(path)


def load_cache(state_dir: Path) -> Optional[CachedFeed]:
    try:
        payload = json.loads(cache_path(state_dir).read_text(encoding="utf-8"))
        rows = [PublicRow(
            hostname=str(r.get("hostname", "")), ip=str(r.get("ip", "")),
            country_long=str(r.get("country_long", "")), country_short=str(r.get("country_short", "")),
            score=str(r.get("score", "")), ping=str(r.get("ping", "")),
            config_b64=str(r.get("config_b64", "")),
        ) for r in payload.get("rows", [])]
        return CachedFeed(rows=rows, fetched_at_ms=int(payload.get("fetched_at_ms", 0)))
    except (OSError, ValueError, TypeError, AttributeError):
        return None


def fetch_live(fetcher: Callable[[], str]) -> List[PublicRow]:
    """Run the injected fetcher, enforce the size cap, parse."""
    text = fetcher()
    if len(text.encode("utf-8", errors="ignore")) > MAX_FEED_BYTES:
        raise ValueError("the public server feed was larger than Sphinx will accept")
    return parse_feed(text)


class _NoRedirect(urllib.request.HTTPRedirectHandler):
    """Refuse urllib's automatic redirects. The Android edition's
    fetcher does not follow redirects for this feed at all (a
    redirect off the feed's own HTTPS answer is a failure, not a
    detour), and urllib's default handling would follow one even
    to plain HTTP — silently breaking this fetch's HTTPS rule.
    Returning None makes urllib raise HTTPError on any redirect,
    which get_directory turns into the cache/empty fallback."""

    def redirect_request(self, req, fp, code, msg, headers, newurl):
        return None


_NO_REDIRECT_OPENER = urllib.request.build_opener(_NoRedirect)


def _open_no_redirect(request, timeout=None):
    """The production opener for the feed fetch: urllib, with
    redirects refused (see _NoRedirect)."""
    return _NO_REDIRECT_OPENER.open(request, timeout=timeout)


def default_fetcher() -> str:
    """The production fetch: HTTPS (redirects refused outright,
    so no hop can downgrade to plain HTTP — the Android fetcher's
    discipline), timeout-bounded, size-capped while reading
    (never an unbounded download)."""
    req = urllib.request.Request(FEED_URL, headers={"User-Agent": "Sphinx"})
    with _open_no_redirect(req, timeout=FETCH_TIMEOUT_S) as resp:
        raw = resp.read(MAX_FEED_BYTES + 1)
    if len(raw) > MAX_FEED_BYTES:
        raise ValueError("the public server feed was larger than Sphinx will accept")
    return raw.decode("utf-8", errors="replace")


@dataclass
class DirectoryResult:
    rows: List[PublicRow] = field(default_factory=list)
    live: bool = False
    cache: Optional[CachedFeed] = None
    error: str = ""


def get_directory(state_dir: Path, fetcher: Optional[Callable[[], str]] = None) -> DirectoryResult:
    """Live first; on any failure, the cache (labeled by the
    caller with its age); no cache + dead feed = empty rows."""
    try:
        rows = fetch_live(fetcher or default_fetcher)
        if not rows:
            raise ValueError("the public server feed carried no usable servers")
        try:
            save_cache(state_dir, rows)
        except OSError:
            pass  # listing live must not fail because caching did
        return DirectoryResult(rows=rows, live=True)
    except Exception as exc:  # network, parse, size — all the same honest fallback
        cached = load_cache(state_dir)
        if cached is not None and cached.rows:
            return DirectoryResult(rows=cached.rows, live=False, cache=cached, error=str(exc))
        return DirectoryResult(rows=[], live=False, cache=None, error=str(exc))
