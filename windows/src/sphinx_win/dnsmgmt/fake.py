"""An in-memory DnsManager for tests and dry runs. It behaves like
the Windows manager's contract: adapters have per-family server
lists, empty means DHCP, and failures can be injected per adapter.
"""
from __future__ import annotations

from typing import Dict, List, Tuple

from .base import AdapterDns


class FakeDnsManager:
    def __init__(self, adapters: List[AdapterDns], elevated: bool = True):
        self._state: Dict[Tuple[str, str], List[str]] = {
            (a.interface_alias, a.family): list(a.servers) for a in adapters
        }
        self._order = [(a.interface_alias, a.family) for a in adapters]
        self._elevated = elevated
        #: (alias, family) pairs whose set_dns should raise.
        self.fail_on_set: set = set()

    def is_elevated(self) -> bool:
        return self._elevated

    def active_adapters(self) -> List[AdapterDns]:
        return [
            AdapterDns(alias, family, list(self._state[(alias, family)]))
            for alias, family in self._order
        ]

    def get_dns(self, interface_alias: str, family: str) -> List[str]:
        return list(self._state.get((interface_alias, family), []))

    def effective_dns_servers(self) -> List[str]:
        """The fake's effective servers: its current per-adapter
        lists, flattened in adapter order, duplicates removed. (A
        real DHCP adapter's effective servers are its learned ones;
        the fake's state *is* its effective state.)"""
        seen: List[str] = []
        for alias, family in self._order:
            for server in self._state[(alias, family)]:
                if server not in seen:
                    seen.append(server)
        return seen

    def set_dns(self, interface_alias: str, family: str, servers: List[str]) -> None:
        if (interface_alias, family) in self.fail_on_set:
            raise RuntimeError(f"injected failure on {interface_alias}/{family}")
        self._state[(interface_alias, family)] = list(servers)
