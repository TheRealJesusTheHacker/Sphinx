"""The list sanity gate (FILTER-SPEC, "List updates").

A port of the gate in the Android edition's ``core/ListValidation.kt``
(the parse-and-validate half; list *download* sources and redirect
discipline belong to the list-update phase, not Phase 1).
"""
from __future__ import annotations

from typing import Iterable, Optional

from .blocklist import Blocklist

#: A real blocklist holds thousands of domains. A file that parses to
#: fewer than this — an error page, a truncated file, an empty
#: response — is not a blocklist, no matter how it arrived.
DEFAULT_MIN_DOMAINS = 1_000


def is_acceptable(blocklist: Blocklist, min_domains: int = DEFAULT_MIN_DOMAINS) -> bool:
    return blocklist.size >= min_domains


def parse_and_validate(
    lines: Iterable[str], min_domains: int = DEFAULT_MIN_DOMAINS
) -> Optional[Blocklist]:
    """Parse list text and return it only if it passes the sanity gate."""
    parsed = Blocklist.from_lines(lines)
    return parsed if is_acceptable(parsed, min_domains) else None
