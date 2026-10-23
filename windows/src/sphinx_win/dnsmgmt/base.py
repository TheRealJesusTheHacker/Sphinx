"""The DNS-management interface and shared types.

A ``DnsManager`` reads and writes the DNS server settings of the
machine's network adapters. The production implementation drives
Windows (PowerShell's DnsClient cmdlets); tests use an in-memory
fake implementing the same interface, which is where the engage /
restore discipline in ``guard.py`` is proven.
"""
from __future__ import annotations

from dataclasses import dataclass, field
from typing import List, Protocol

#: Address families as the platform names them.
FAMILY_V4 = "IPv4"
FAMILY_V6 = "IPv6"


@dataclass
class AdapterDns:
    """One adapter's DNS servers for one address family.

    ``servers`` empty means the adapter takes its DNS servers from
    DHCP (Windows shows "Obtain DNS server address automatically");
    restoring that state means resetting, not setting an empty list.
    """

    interface_alias: str
    family: str  # FAMILY_V4 or FAMILY_V6
    servers: List[str] = field(default_factory=list)

    @property
    def dhcp(self) -> bool:
        return len(self.servers) == 0

    def to_dict(self) -> dict:
        return {
            "interface_alias": self.interface_alias,
            "family": self.family,
            "servers": list(self.servers),
        }

    @classmethod
    def from_dict(cls, raw: dict) -> "AdapterDns":
        return cls(
            interface_alias=str(raw["interface_alias"]),
            family=str(raw["family"]),
            servers=[str(s) for s in raw.get("servers", [])],
        )


class NotElevatedError(RuntimeError):
    """Raised when a DNS change is attempted without administrator
    rights. The check happens before anything is touched: a
    non-elevated run changes nothing and says so plainly."""


#: Alias kept readable at call sites.
ElevationRequired = NotElevatedError


class DnsManager(Protocol):
    """Reads and writes adapter DNS settings. Implementations must
    only ever be invoked through DnsGuard, which owns the
    save-before-change discipline."""

    def is_elevated(self) -> bool:
        """True when this process may change DNS settings."""
        ...

    def active_adapters(self) -> List[AdapterDns]:
        """DNS state for the adapters that actually carry the
        machine's connections (up, with a default route) — both
        families for each."""
        ...

    def get_dns(self, interface_alias: str, family: str) -> List[str]:
        """The adapter's CONFIGURED DNS servers for ``family``
        (empty = automatic/DHCP). Configured, not effective: an
        implementation must never report the addresses DHCP handed
        out as if they were a static configuration — recording
        those as an "original" would make a later restore pin them
        statically instead of returning the adapter to automatic."""
        ...

    def set_dns(self, interface_alias: str, family: str, servers: List[str]) -> None:
        """Set static DNS servers for the adapter/family. An empty
        list resets the adapter to DHCP-provided DNS."""
        ...

    def effective_dns_servers(self) -> List[str]:
        """The DNS servers the machine is *effectively* using right
        now, across the active adapters, in the order the adapters
        report them — DHCP-learned addresses included. This is the
        forwarding chain's floor (FILTER-SPEC): the resolvers that
        were answering this machine before Sphinx engaged. It is
        captured before any change, never read from an engaged
        machine (whose effective servers are the filter's own
        loopbacks), and it is never a restore value — restores use
        the configured servers recorded in the backup, exactly.
        Loopbacks may appear here (another local resolver); the
        chain builder refuses them as floor entries."""
        ...
