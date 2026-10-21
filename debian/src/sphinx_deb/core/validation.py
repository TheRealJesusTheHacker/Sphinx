"""List sources, the sanity gate, and redirect discipline —
FILTER-SPEC, "List updates".

The gate half is a port of the Android edition's
``core/ListValidation.kt``; the sources and redirect vetting are
the same edition's rules in the same shape the Windows edition's
Python core carries them. Phase 1 shipped the gate alone (there
was nothing to download with); Phase 2 adds the sources and the
redirect discipline the updater runs under.
"""
from __future__ import annotations

from dataclasses import dataclass
from typing import Iterable, Optional
from urllib.parse import urljoin

from .blocklist import Blocklist

#: A real blocklist holds thousands of domains. A file that parses to
#: fewer than this — an error page, a truncated file, an empty
#: response — is not a blocklist, no matter how it arrived.
DEFAULT_MIN_DOMAINS = 1_000


@dataclass(frozen=True)
class ListSource:
    """A named source a blocklist can be downloaded from. The URLs
    are user-visible — an edition fetches only from the sources it
    shows. These defaults are simply where a fresh install points."""

    name: str
    url: str


def is_acceptable_url(url: str) -> bool:
    """Only HTTPS sources are accepted — a blocklist is a security
    control, so it never travels over a tamperable channel."""
    return url.startswith("https://") and len(url) > len("https://")


DEFAULT_SOURCES = (
    ListSource(
        "StevenBlack — ads & malware (unified hosts)",
        "https://raw.githubusercontent.com/StevenBlack/hosts/master/hosts",
    ),
    ListSource(
        "HaGeZi — Multi LIGHT (ads, trackers, telemetry)",
        "https://raw.githubusercontent.com/hagezi/dns-blocklists/main/wildcard/light.txt",
    ),
)


def is_acceptable(blocklist: Blocklist, min_domains: int = DEFAULT_MIN_DOMAINS) -> bool:
    return blocklist.size >= min_domains


def parse_and_validate(
    lines: Iterable[str], min_domains: int = DEFAULT_MIN_DOMAINS
) -> Optional[Blocklist]:
    """Parse list text and return it only if it passes the sanity gate."""
    parsed = Blocklist.from_lines(lines)
    return parsed if is_acceptable(parsed, min_domains) else None


def redirect_target(current_url: str, location: Optional[str]) -> Optional[str]:
    """Where a redirect may take a list download.

    ``location`` (a raw ``Location`` header value) is resolved against
    ``current_url``; the result is returned only if the download stays
    on HTTPS. Sources are HTTPS-only, and that has to hold for *every
    hop*: a redirect that downgrades to plain HTTP would hand the list
    to anyone on the network path, who could substitute a different
    real-shaped list. The platform's automatic redirect handling is
    not trusted to refuse a downgrade, so editions follow redirects by
    hand through this check — every hop, on whatever host it lands,
    is vetted on its own before it is followed. A redirect to another
    HTTPS host (a CDN, a mirror) is fine. None — a missing or
    unusable Location, or any non-HTTPS hop — fails the download, and
    a failed download changes nothing.
    """
    target = (location or "").strip()
    if not target:
        return None
    try:
        resolved = urljoin(current_url, target)
    except Exception:
        return None
    return resolved if is_acceptable_url(resolved) else None
