"""The tunnel-management interface and shared types.

A ``TunnelManager`` drives one WireGuard tunnel on the machine.
The production implementation hosts WireGuardNT's official
``wireguard.dll`` inside the tray process (the embed route —
see windows/README.md, "VPN mode" for the evaluation and the
license evidence); tests use an in-memory fake implementing the
same interface, which is where the mode model is proven.

Ownership: exactly one tunnel, owned by the one tray-resident
process that already owns the window, the filter, and the DNS
guard state. No second program owns tunnel state.

Licensing, stated precisely: WireGuardNT is **bundled** — the
prebuilt ``wireguard.dll`` from the official wireguard-nt
distribution ships UNMODIFIED beside Sphinx, under WireGuard
LLC's Prebuilt Binaries License (redistribution alongside
software that uses it only via the Permitted API of
``wireguard.h`` is expressly allowed), with that license text
shipped alongside. Nothing GPL is linked or copied.
"""
from __future__ import annotations

import time
from dataclasses import dataclass
from typing import Optional, Protocol, Tuple

#: A handshake older than this is stale: WireGuard rekeys roughly
#: every two minutes while traffic flows, so three minutes without
#: a fresh handshake means the tunnel is not carrying anything —
#: the kill-switch state, never "connected".
HANDSHAKE_FRESH_MS = 180_000


@dataclass
class TunnelStatus:
    """The backend's report — the ONLY basis for claiming
    "connected" (TUNNEL-SPEC: never from intent, configuration,
    or a process merely running)."""

    adapter_up: bool
    latest_handshake_ms: Optional[int] = None  # unix ms; None = never
    rx_bytes: int = 0
    tx_bytes: int = 0

    def handshake_fresh(self, now_ms: Optional[int] = None) -> bool:
        if self.latest_handshake_ms is None:
            return False
        now = now_ms if now_ms is not None else int(time.time() * 1000)
        return 0 <= now - self.latest_handshake_ms <= HANDSHAKE_FRESH_MS


class TunnelError(RuntimeError):
    """A tunnel operation failed, with the reason in the message."""


class TunnelUnavailable(TunnelError):
    """The tunnel backend cannot run on this machine at all (not
    Windows, or the bundled wireguard.dll is missing)."""


class TunnelNotElevated(TunnelError):
    """A tunnel change was attempted without administrator rights.
    Checked before anything is touched: a non-elevated attempt
    changes nothing and says so plainly."""


class TunnelManager(Protocol):
    """Drives the one tunnel. Implementations must only ever be
    invoked through the controller's mode model, which owns the
    ordering (resolve + pin first, tunnel up, DNS per mode,
    ordinary stop path back)."""

    def is_elevated(self) -> bool:
        """True when this process may create adapters and routes."""
        ...

    def availability(self) -> Tuple[bool, str]:
        """(usable, reason) — the reason is plain language for the
        UI when the backend cannot run here."""
        ...

    def up(self, profile, *, endpoint_ip: str, endpoint_port: int) -> None:
        """Bring the tunnel up for ``profile``, with the endpoint
        PINNED to the address resolved before engagement. Raises
        TunnelError on failure, leaving routes as they were or
        the adapter up-but-unhandshaked (the kill-switch state) —
        never a silent direct route for covered traffic."""
        ...

    def down(self) -> None:
        """Take the tunnel down and remove its routes/adapter."""
        ...

    def status(self) -> TunnelStatus:
        """The backend's live report (adapter + latest handshake)."""
        ...

    def generate_keypair(self) -> Tuple[str, str]:
        """A fresh (private, public) pair from a vetted means —
        see core.tunnel.generate_keypair. Never hand-rolled."""
        ...
