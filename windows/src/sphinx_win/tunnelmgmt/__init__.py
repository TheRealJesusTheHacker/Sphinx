"""Tunnel management for VPN mode: bring the one WireGuard
tunnel up and down and report its real state, under the same
discipline shape as dnsmgmt (an interface in base.py, a fake for
tests, the real Windows implementation beside it).

The route: WireGuardNT's official prebuilt ``wireguard.dll``,
BUNDLED unmodified and hosted by the tray process (the embed
route — windows/README.md has the evaluation and the license
evidence). Tunnel state itself is a parallel record in
core.tunnelstore — never a rewrite of the DNS backup contract.
"""
from .base import (
    HANDSHAKE_FRESH_MS,
    TunnelError,
    TunnelManager,
    TunnelNotElevated,
    TunnelStatus,
    TunnelUnavailable,
)

__all__ = [
    "HANDSHAKE_FRESH_MS",
    "TunnelError",
    "TunnelManager",
    "TunnelNotElevated",
    "TunnelStatus",
    "TunnelUnavailable",
]
