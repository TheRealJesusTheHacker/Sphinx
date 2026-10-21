"""System DNS management: record the machine's current DNS settings,
point them at the local filter, and restore them exactly.

This is the careful part of the Windows edition, and it follows the
fleet's restore discipline (Charon's toll): the original settings
are saved BEFORE any change, the save is verified by reading it
back, and the machine is never left pointing at a resolver that
isn't answering.
"""
from .base import AdapterDns, DnsManager, ElevationRequired, NotElevatedError
from .guard import DnsGuard, DnsState, EngageResult, RestoreResult

__all__ = [
    "AdapterDns",
    "DnsManager",
    "ElevationRequired",
    "NotElevatedError",
    "DnsGuard",
    "DnsState",
    "EngageResult",
    "RestoreResult",
]
