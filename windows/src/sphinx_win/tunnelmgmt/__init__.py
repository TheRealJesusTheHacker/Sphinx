"""Tunnel management for VPN mode: bring the one WireGuard
tunnel up and down and report its real state, under the same
discipline shape as dnsmgmt (an interface in base.py, a fake for
tests, the real Windows implementation beside it).

The route: WireGuardNT's official prebuilt ``wireguard.dll``,
BUNDLED unmodified and hosted by the tray process (the embed
route — windows/README.md has the evaluation and the license
evidence). Tunnel state itself is a parallel record in
core.tunnelstore — never a rewrite of the DNS backup contract.

Phase 2 adds the OpenVPN engine beside it, under the same
base/fake/impl discipline (openvpn_base.py, openvpn_fake.py,
openvpn_windows_impl.py): the user's own installed
``openvpn.exe``, INVOKED at arm's length (GPLv2, never bundled),
supervised as a child of the same one tray process, fed only a
sanitized config (core.openvpn_sanitize).
"""
from .base import (
    HANDSHAKE_FRESH_MS,
    TunnelError,
    TunnelManager,
    TunnelNotElevated,
    TunnelStatus,
    TunnelUnavailable,
)
from .openvpn_base import OPENVPN_NOT_INSTALLED_MESSAGE, OpenVpnManager

__all__ = [
    "HANDSHAKE_FRESH_MS",
    "TunnelError",
    "TunnelManager",
    "TunnelNotElevated",
    "TunnelStatus",
    "TunnelUnavailable",
    "OPENVPN_NOT_INSTALLED_MESSAGE",
    "OpenVpnManager",
]
