"""The platform-neutral filter core: parsing, matching, validation,
storage, updating, forwarding, and the DNS filter server. No Windows
APIs live in this package — it is the FILTER-SPEC brain, and it is
unit-tested on any platform.
"""
from .blocklist import Allowlist, Blocklist, FilterLists, normalize, normalize_entry, parse_entries
from .querylog import QueryLog, QueryLogEntry
from .validation import (
    DEFAULT_MIN_DOMAINS,
    DEFAULT_SOURCES,
    ListSource,
    is_acceptable,
    is_acceptable_url,
    parse_and_validate,
    redirect_target,
)

__all__ = [
    "Allowlist",
    "Blocklist",
    "FilterLists",
    "normalize",
    "normalize_entry",
    "parse_entries",
    "QueryLog",
    "QueryLogEntry",
    "DEFAULT_MIN_DOMAINS",
    "DEFAULT_SOURCES",
    "ListSource",
    "is_acceptable",
    "is_acceptable_url",
    "parse_and_validate",
    "redirect_target",
]
