"""An in-memory TunnelManager for tests and dry runs.

It models the contract the mode model depends on:

- ``up`` records the profile and the PINNED endpoint it was
  handed (the model must resolve before it engages, and the
  manager must be given the pin, never the hostname).
- ``status`` reports a handshake whose freshness the test
  controls; ``drop_tunnel()`` simulates the server going away
  mid-session — the adapter and its routes STAY (that is the
  kill switch), the handshake goes stale, and covered traffic
  blackholes.
- ``send_packet`` is the data-plane MODEL, at the level this
  fake honestly supports: it answers "would a packet to this
  destination be carried by the tunnel right now?" — carried
  when the tunnel is up with a fresh handshake and the
  destination is inside the profile's allowed IPs; carried
  directly (not through the tunnel) when the tunnel is down,
  which is the machine's ordinary pre-VPN state; blackholed
  (False, and not direct either) while the kill switch holds.
  It is a model of the OS routing the real backend programs,
  not a claim about real packets — the conformance tests that
  use it say exactly that.
- Keypairs come from the corpus's clearly-marked EXAMPLE keys —
  test material only, protecting nothing.
"""
from __future__ import annotations

import ipaddress
import time
from typing import List, Optional, Tuple

from .base import TunnelError, TunnelNotElevated, TunnelStatus

#: EXAMPLE keys (from docs/tunnel-corpus.json — generated for
#: tests, not real key material).
EXAMPLE_PRIVATE_KEY = "hI9byVWLK8639iOPJ8Z3ej9sp4rhqOdnHQ3pfp0N35s="
EXAMPLE_PUBLIC_KEY = "q6GQz9IBykkuC3C+kX7l8w7SU9s6yP0Vq8UurgHsiFU="


class FakeTunnelManager:
    def __init__(
        self,
        elevated: bool = True,
        available: bool = True,
        handshake_age_ms: int = 1_000,
    ):
        self._elevated = elevated
        self._available = available
        self._handshake_age_ms = handshake_age_ms
        self.adapter_up = False
        self.profile = None
        self.pinned: Optional[Tuple[str, int]] = None
        self.up_calls: List[Tuple[object, str, int]] = []
        self.down_calls = 0
        self.fail_on_up: Optional[Exception] = None
        self._dropped = False
        self.rx_bytes = 0
        self.tx_bytes = 0
        #: Settable clock offset for freshness tests.
        self.extra_age_ms = 0

    # --- Contract -------------------------------------------------

    def is_elevated(self) -> bool:
        return self._elevated

    def availability(self):
        if self._available:
            return True, ""
        return False, "the WireGuard component is not available (fake)"

    def up(self, profile, *, endpoint_ip: str, endpoint_port: int) -> None:
        if not self._elevated:
            raise TunnelNotElevated(
                "Changing routes for a VPN needs administrator "
                "rights; nothing was changed."
            )
        if self.fail_on_up is not None:
            raise self.fail_on_up
        self.up_calls.append((profile, endpoint_ip, endpoint_port))
        self.profile = profile
        self.pinned = (endpoint_ip, endpoint_port)
        self.adapter_up = True
        self._dropped = False

    def down(self) -> None:
        self.down_calls += 1
        self.adapter_up = False
        self.profile = None
        self.pinned = None
        self._dropped = False

    def status(self) -> TunnelStatus:
        if not self.adapter_up:
            return TunnelStatus(adapter_up=False)
        if self._dropped:
            handshake = None
        else:
            handshake = (
                int(time.time() * 1000)
                - self._handshake_age_ms
                - self.extra_age_ms
            )
        return TunnelStatus(
            adapter_up=True,
            latest_handshake_ms=handshake,
            rx_bytes=self.rx_bytes,
            tx_bytes=self.tx_bytes,
        )

    def generate_keypair(self):
        return EXAMPLE_PRIVATE_KEY, EXAMPLE_PUBLIC_KEY

    # --- Test controls --------------------------------------------

    def drop_tunnel(self) -> None:
        """The server stops answering mid-session. The adapter and
        routes stay up (kill switch); the handshake goes stale."""
        self._dropped = True

    def send_packet(self, destination: str) -> str:
        """The data-plane model (see the module docstring):
        "tunnel" = carried by the tunnel, "direct" = the
        machine's ordinary route (tunnel down), "blocked" =
        blackholed by the kill switch."""
        if not self.adapter_up:
            return "direct"
        if self._dropped or not self.status().handshake_fresh():
            return "blocked"
        dest = ipaddress.ip_address(destination)
        for peer in getattr(self.profile, "peers", []):
            for cidr in peer.allowed_ips:
                if dest in ipaddress.ip_network(cidr, strict=False):
                    return "tunnel"
        return "direct"  # outside the tunnel's coverage: split path
