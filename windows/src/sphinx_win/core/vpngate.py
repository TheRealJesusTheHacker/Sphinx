"""The VPN Gate public-nodes directory (TUNNEL-SPEC, Phase 2,
"Public volunteer servers" — normative).

VPN Gate (University of Tsukuba's academic research project)
publishes the volunteer relay servers it knows about as a CSV
feed whose rows carry country, score, and the server's whole
OpenVPN config as base64. This module is the directory model
behind the picker's "Public volunteer servers" section:

- **Fetched fresh at use time** — the list churns hourly, so
  nothing is bundled and nothing cached is ever presented as
  live. The fetch is HTTPS-only, size-capped, and
  timeout-bounded.
- **Cached with its fetch timestamp.** A cache may be shown
  with its age labeled ("list from 2 hours ago"); a dead feed
  with no cache is an honest empty state — never last week's
  servers dressed as today's.
- **Rows become OpenVPN profiles.** A row's label is
  "Public volunteer server — <Country> (<host>)"; its config is
  an ordinary OpenVPN config, which the connect path sanitizes
  like any stranger's config (core.openvpn_sanitize) — feed
  rows above all.
- **The disclosure rides at the point of use** — in the picker
  section and again in the connect confirmation. The text is
  VPNGATE_DISCLOSURE below, verbatim, and the test suite pins
  its presence in both places.

Tests never touch the live feed: the parser is proven against a
synthetic fixture in the feed's exact format, and the fetch is
injected everywhere it is used in tests.
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
from typing import Callable, List, Optional

#: The one feed, fetched over HTTPS only, at use time.
FEED_URL = "https://www.vpngate.net/api/iphone/"

#: Bounds on the fetch: the list churns hourly and carries whole
#: configs, so it is megabytes, not gigabytes — a response past
#: the cap is not the feed and is refused whole.
MAX_FEED_BYTES = 16 * 1024 * 1024
FETCH_TIMEOUT_S = 15.0

CACHE_FILE_NAME = "vpngate-cache.json"

#: The disclosure, at the point of use (picker + connect
#: confirmation), substantially as TUNNEL-SPEC requires. A
#: directory shipped without this warning, in those places, is
#: a spec violation — the suite pins it.
VPNGATE_DISCLOSURE = (
    "These are strangers' machines, volunteered to a research "
    "project (VPN Gate, University of Tsukuba). The operator "
    "can see your traffic. VPN Gate states its servers keep "
    "connection logs — your real address, the times, the server "
    "you used — for three months or more. Fine for appearing "
    "to be somewhere else; not for anything sensitive."
)

#: The section's own heading/label, verbatim — distinct from the
#: user's profiles in words as well as in place.
PUBLIC_SECTION_TITLE = "Public volunteer servers"
PUBLIC_SECTION_NOTE = (
    "Public volunteer servers — run by strangers, not Sentinel's "
    "servers, not Sphinx servers. This list is fetched when you "
    "open it; nothing here is bundled or pre-enabled."
)


@dataclass
class VpnGateServer:
    """One feed row: the facts the picker shows plus the row's
    OpenVPN config text (decoded from the feed's base64 column)."""

    host_name: str
    ip: str
    score: str
    ping: str
    speed: str
    country_long: str
    country_short: str
    sessions: str
    uptime: str
    operator: str
    message: str
    config_text: str = field(repr=False)

    @property
    def label(self) -> str:
        """How the row is named as a connection choice — always
        marked as what it is, never dressed as the user's own."""
        country = self.country_long or self.country_short or "Unknown"
        return f"Public volunteer server — {country} ({self.host_name})"

    def to_dict(self) -> dict:
        return {
            "host_name": self.host_name,
            "ip": self.ip,
            "score": self.score,
            "ping": self.ping,
            "speed": self.speed,
            "country_long": self.country_long,
            "country_short": self.country_short,
            "sessions": self.sessions,
            "uptime": self.uptime,
            "operator": self.operator,
            "message": self.message,
            "config_text": self.config_text,
        }

    @classmethod
    def from_dict(cls, raw: dict) -> "VpnGateServer":
        return cls(
            host_name=str(raw.get("host_name", "")),
            ip=str(raw.get("ip", "")),
            score=str(raw.get("score", "")),
            ping=str(raw.get("ping", "")),
            speed=str(raw.get("speed", "")),
            country_long=str(raw.get("country_long", "")),
            country_short=str(raw.get("country_short", "")),
            sessions=str(raw.get("sessions", "")),
            uptime=str(raw.get("uptime", "")),
            operator=str(raw.get("operator", "")),
            message=str(raw.get("message", "")),
            config_text=str(raw.get("config_text", "")),
        )


class VpnGateFeedError(RuntimeError):
    """The feed could not be fetched or parsed. The message is
    the honest empty-state sentence for the UI."""


EMPTY_STATE_MESSAGE = (
    "Couldn't fetch the list — check your connection. No public "
    "servers are shown, because a list Sphinx cannot fetch is "
    "never replaced with an old or bundled one presented as new."
)


def parse_feed(text: str) -> List[VpnGateServer]:
    """Parse the feed's CSV text into rows.

    The feed's exact shape: a ``*vpn_servers`` line, a header
    line beginning ``#HostName``, one CSV row per server, and a
    closing ``*`` line. Rows whose config column is not decodable
    base64, or that decode to text with no OpenVPN shape, are
    skipped — a directory row Sphinx cannot connect is worse
    than no row. A text with no header at all is not the feed
    and raises VpnGateFeedError."""
    lines = [ln for ln in text.splitlines() if ln.strip()]
    header_index = None
    for i, line in enumerate(lines):
        if line.lstrip().startswith("#HostName"):
            header_index = i
            break
    if header_index is None:
        raise VpnGateFeedError(
            "That response was not the VPN Gate list (no server "
            "header in it), so nothing was shown from it."
        )
    header = lines[header_index].lstrip()
    if header.startswith("#"):
        header = header[1:]
    body = [ln for ln in lines[header_index + 1 :] if ln.strip() != "*"]
    reader = csv.DictReader(io.StringIO("\n".join([header, *body])))
    servers: List[VpnGateServer] = []
    for row in reader:
        try:
            raw_config = (row.get("OpenVPN_ConfigData_Base64") or "").strip()
            if not raw_config:
                continue
            config_text = base64.b64decode(
                raw_config.encode("ascii"), validate=True
            ).decode("utf-8", errors="strict")
        except (binascii.Error, ValueError, UnicodeDecodeError):
            continue
        if "remote " not in config_text:
            continue
        servers.append(
            VpnGateServer(
                host_name=(row.get("HostName") or "").strip(),
                ip=(row.get("IP") or "").strip(),
                score=(row.get("Score") or "").strip(),
                ping=(row.get("Ping") or "").strip(),
                speed=(row.get("Speed") or "").strip(),
                country_long=(row.get("CountryLong") or "").strip(),
                country_short=(row.get("CountryShort") or "").strip(),
                sessions=(row.get("NumVpnSessions") or "").strip(),
                uptime=(row.get("Uptime") or "").strip(),
                operator=(row.get("Operator") or "").strip(),
                message=(row.get("Message") or "").strip(),
                config_text=config_text,
            )
        )
    return servers


class _NoRedirect(urllib.request.HTTPRedirectHandler):
    """Refuse urllib's automatic redirects. The Android edition's
    fetcher does not follow redirects for this feed at all (a
    redirect off the feed's own HTTPS answer is a failure, not a
    detour), and urllib's default handling would follow one even
    to plain HTTP — silently breaking this module's HTTPS-only
    rule. Returning None makes urllib raise HTTPError on any
    redirect, which the fetch turns into the honest failure."""

    def redirect_request(self, req, fp, code, msg, headers, newurl):
        return None


_NO_REDIRECT_OPENER = urllib.request.build_opener(_NoRedirect)


def _open_no_redirect(request, timeout=None):
    """The production opener for the feed fetch: urllib, with
    redirects refused (see _NoRedirect). Matches the ``opener``
    injection seam's (request, timeout) shape."""
    return _NO_REDIRECT_OPENER.open(request, timeout=timeout)


def fetch_feed_text(
    url: str = FEED_URL,
    *,
    timeout: float = FETCH_TIMEOUT_S,
    max_bytes: int = MAX_FEED_BYTES,
    opener: Optional[Callable] = None,
) -> str:
    """Fetch the feed text, bounded: HTTPS only (redirects are
    refused outright, so no hop can downgrade to plain HTTP —
    the Android fetcher's discipline), a hard timeout, and a
    hard size cap (the response is read to the cap + 1 and
    refused past it — never buffered unbounded). ``opener`` is
    the injection seam for tests; production uses urllib
    through _open_no_redirect."""
    if not url.lower().startswith("https://"):
        raise VpnGateFeedError("The server list is fetched over HTTPS only.")
    request = urllib.request.Request(
        url, headers={"User-Agent": "Sphinx (VPN Gate directory)"}
    )
    open_fn = opener or _open_no_redirect
    try:
        with open_fn(request, timeout=timeout) as response:
            raw = response.read(max_bytes + 1)
    except VpnGateFeedError:
        raise
    except Exception as e:
        raise VpnGateFeedError(EMPTY_STATE_MESSAGE) from e
    if len(raw) > max_bytes:
        raise VpnGateFeedError(
            "The server list response was larger than the list can "
            "honestly be, so it was refused whole and nothing was "
            "shown from it."
        )
    return raw.decode("utf-8", errors="replace")


def format_age(age_seconds: float) -> str:
    """The cache-age label's phrasing: "2 hours ago" and friends —
    the age is always stated, never smoothed into "live"."""
    seconds = max(0, int(age_seconds))
    if seconds < 60:
        return "under a minute ago"
    if seconds < 3600:
        minutes = seconds // 60
        return f"{minutes} minute{'s' if minutes != 1 else ''} ago"
    if seconds < 86400:
        hours = seconds // 3600
        return f"{hours} hour{'s' if hours != 1 else ''} ago"
    days = seconds // 86400
    return f"{days} day{'s' if days != 1 else ''} ago"


@dataclass
class DirectoryListing:
    """What the picker shows: rows, where they came from, and the
    freshness sentence that must ride with them."""

    servers: List[VpnGateServer]
    #: "live" (just fetched), "cache" (a labeled older copy), or
    #: "empty" (dead feed, no cache — the honest empty state).
    source: str
    fetched_at: Optional[float] = None  # unix seconds
    message: str = ""

    def freshness_text(self, now: Optional[float] = None) -> str:
        now = time.time() if now is None else now
        if self.source == "live":
            return "List fetched just now, from VPN Gate."
        if self.source == "cache" and self.fetched_at is not None:
            return (
                "List from cache — fetched "
                + format_age(now - self.fetched_at)
                + ". It is shown as an older list, not as today's."
            )
        return EMPTY_STATE_MESSAGE


class VpnGateDirectory:
    """The directory model: fetch-at-use-time, cache with a
    timestamp, stale labeled, dead feed honest.

    ``fetcher`` returns feed TEXT (production: fetch_feed_text);
    tests inject synthetic text or a failing fetcher — the model
    never knows the difference and never touches the network on
    its own: nothing is fetched until ``refresh()`` is called,
    which happens only when the user opens the section."""

    def __init__(
        self,
        data_dir: Path,
        fetcher: Optional[Callable[[], str]] = None,
    ):
        self.data_dir = Path(data_dir)
        self.cache_file = self.data_dir / CACHE_FILE_NAME
        self._fetcher = fetcher or fetch_feed_text

    # --- Cache ----------------------------------------------------

    def _read_cache(self):
        if not self.cache_file.is_file():
            return None
        try:
            raw = json.loads(self.cache_file.read_text(encoding="utf-8"))
            fetched_at = float(raw["fetched_at"])
            servers = [VpnGateServer.from_dict(d) for d in raw["servers"]]
        except Exception:
            # A cache that cannot be read honestly is no cache:
            # the empty state beats a dressed-up guess. (The file
            # is a cache, not a record — the store disciplines
            # for records do not apply to it.)
            return None
        return fetched_at, servers

    def _write_cache(self, fetched_at: float, servers) -> None:
        try:
            self.data_dir.mkdir(parents=True, exist_ok=True)
            payload = {
                "fetched_at": fetched_at,
                "servers": [s.to_dict() for s in servers],
            }
            self.cache_file.write_text(
                json.dumps(payload), encoding="utf-8"
            )
        except OSError:
            pass  # caching is best-effort; the live list still shows

    # --- Use --------------------------------------------------------

    def refresh(self, now: Optional[float] = None) -> DirectoryListing:
        """Fetch the list now. On success the listing is live and
        the cache is replaced; on failure the cache is shown WITH
        ITS AGE, or — with no cache — the honest empty state."""
        now = time.time() if now is None else now
        try:
            text = self._fetcher()
            servers = parse_feed(text)
        except Exception:
            cached = self._read_cache()
            if cached is not None:
                fetched_at, servers = cached
                return DirectoryListing(
                    servers=servers, source="cache", fetched_at=fetched_at
                )
            return DirectoryListing(servers=[], source="empty")
        if not servers:
            # A fetched-but-empty parse is a failure to be honest
            # about, not a directory of zero strangers.
            cached = self._read_cache()
            if cached is not None:
                fetched_at, cached_servers = cached
                return DirectoryListing(
                    servers=cached_servers, source="cache",
                    fetched_at=fetched_at,
                )
            return DirectoryListing(servers=[], source="empty")
        self._write_cache(now, servers)
        return DirectoryListing(
            servers=servers, source="live", fetched_at=now
        )

    def cached_listing(self) -> Optional[DirectoryListing]:
        cached = self._read_cache()
        if cached is None:
            return None
        fetched_at, servers = cached
        return DirectoryListing(
            servers=servers, source="cache", fetched_at=fetched_at
        )
