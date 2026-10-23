"""The production TunnelManager: hosts WireGuardNT in-process.

THE ROUTE (evaluated 2026-10-23; the full evaluation and license
evidence are in windows/README.md, "VPN mode"): the tray process
loads the official prebuilt ``wireguard.dll`` from the
wireguard-nt distribution — **bundled, unmodified**, under
WireGuard LLC's Prebuilt Binaries License — and drives it through
the Permitted API of ``wireguard.h`` via ctypes:

  WireGuardCreateAdapter -> WireGuardSetConfiguration ->
  WireGuardSetAdapterState(UP), with the adapter's IP addresses
  and the profile's routes programmed through Windows' own
  networking cmdlets, and status read back through
  WireGuardGetConfiguration (the latest-handshake report is the
  only "connected" proof the mode model accepts).

WireGuardNT is a kernel implementation; it does not use Wintun
(Wintun serves userspace implementations), so ``wintun.dll`` is
not bundled — shipping an unused DLL would misstate what runs.

One process owns the tunnel: this manager lives and dies with
the tray host, exactly like the DNS guard. The supervised
alternative — the official WireGuard for Windows tunnel service
— would put a second owner over tunnel state and a separate
GPLv2 program between Sphinx and its own status; it was not
chosen (README has the weighing).

Honesty boundary: this module imports cleanly on any platform
and its pure parts (the configuration-blob builder, the DLL
search, the struct layout) are unit-tested on Linux, but the
adapter/route/handshake path itself can only be PROVEN on a
real Windows machine — that pass is a named release gate, not
something this code claims by existing.

Sockets note (WireGuardNT's own rule): the adapter's sockets are
owned by the process that sets the adapter up — one more reason
the tunnel belongs to the tray process and nobody else.
"""
from __future__ import annotations

import base64
import ctypes
import ipaddress
import os
import socket
import struct
import subprocess
import sys
import time
from pathlib import Path
from typing import List, Optional, Tuple

from ..core.tunnel import generate_keypair as _generate_keypair
from .base import TunnelError, TunnelNotElevated, TunnelStatus, TunnelUnavailable

ADAPTER_NAME = "Sphinx"
ADAPTER_TUNNEL_TYPE = "WireGuard"
_WIREGUARD_DLL_NAME = "wireguard.dll"
_LICENSE_FILE_NAME = "WireGuardNT-LICENSE.txt"

# wireguard.h flags.
_INTERFACE_HAS_PRIVATE_KEY = 1 << 1
_INTERFACE_REPLACE_PEERS = 1 << 3
_PEER_HAS_PUBLIC_KEY = 1 << 0
_PEER_HAS_PRESHARED_KEY = 1 << 1
_PEER_HAS_PERSISTENT_KEEPALIVE = 1 << 2
_PEER_HAS_ENDPOINT = 1 << 3
_PEER_REPLACE_ALLOWED_IPS = 1 << 5

_ADAPTER_STATE_DOWN = 0
_ADAPTER_STATE_UP = 1

_AF_INET = 2
_AF_INET6 = 23

_WINDOWS_EPOCH_OFFSET_MS = 11_644_473_600_000  # 1601 -> 1970, in ms


# --- wireguard.h structures (ALIGNED(8) in the header) -----------------


class _WireGuardInterface(ctypes.Structure):
    # wireguard.h's ALIGNED(8): member offsets follow the natural
    # layout (PrivateKey at 6, PublicKey at 38, PeersCount at 72)
    # and the struct's stride is padded to 80 — the trailing pad
    # below is that padding, and what follows the interface in a
    # configuration buffer starts at offset 80, not 76.
    _fields_ = [
        ("Flags", ctypes.c_uint32),
        ("ListenPort", ctypes.c_uint16),
        ("PrivateKey", ctypes.c_ubyte * 32),
        ("PublicKey", ctypes.c_ubyte * 32),
        ("PeersCount", ctypes.c_uint32),
        ("_tail_pad", ctypes.c_ubyte * 4),
    ]


class _SockaddrIn(ctypes.Structure):
    _fields_ = [
        ("sin_family", ctypes.c_uint16),
        ("sin_port", ctypes.c_uint16),  # network byte order
        ("sin_addr", ctypes.c_ubyte * 4),
        ("sin_zero", ctypes.c_ubyte * 8),
    ]


class _SockaddrIn6(ctypes.Structure):
    _fields_ = [
        ("sin6_family", ctypes.c_uint16),
        ("sin6_port", ctypes.c_uint16),  # network byte order
        ("sin6_flowinfo", ctypes.c_uint32),
        ("sin6_addr", ctypes.c_ubyte * 16),
        ("sin6_scope_id", ctypes.c_uint32),
    ]


class _SockaddrInet(ctypes.Union):
    _fields_ = [
        ("Ipv4", _SockaddrIn),
        ("Ipv6", _SockaddrIn6),
        ("si_family", ctypes.c_uint16),
    ]


class _WireGuardPeer(ctypes.Structure):
    _fields_ = [
        ("Flags", ctypes.c_uint32),
        ("Reserved", ctypes.c_uint32),
        ("PublicKey", ctypes.c_ubyte * 32),
        ("PresharedKey", ctypes.c_ubyte * 32),
        ("PersistentKeepalive", ctypes.c_uint16),
        ("Endpoint", _SockaddrInet),
        ("TxBytes", ctypes.c_uint64),
        ("RxBytes", ctypes.c_uint64),
        ("LastHandshake", ctypes.c_uint64),
        ("AllowedIPsCount", ctypes.c_uint32),
    ]


class _WireGuardAllowedIp(ctypes.Structure):
    _fields_ = [
        ("Address", ctypes.c_ubyte * 16),
        ("AddressFamily", ctypes.c_uint16),
        ("Cidr", ctypes.c_ubyte),
        ("Flags", ctypes.c_uint32),
    ]


def _key_bytes(b64: str) -> bytes:
    return base64.b64decode(b64.encode("ascii"))


def build_config_blob(profile, *, endpoint_ip: str, endpoint_port: int) -> bytes:
    """Assemble the WIREGUARD_INTERFACE + peers + allowed-IPs
    buffer WireGuardSetConfiguration consumes, with the endpoint
    PINNED to the pre-resolved address (the SOCKADDR_INET the DLL
    takes can only carry an address, never a name — pinning is
    structural here, not a promise). Pure and testable anywhere.

    Raises TunnelError when the profile cannot be represented
    (for example a peer with no endpoint: Phase 1 drives the
    first peer of the profile, and says so)."""
    peers = list(getattr(profile, "peers", []))
    if not peers:
        raise TunnelError("The profile names no server peer.")
    # The adapter's endpoint is the FIRST peer's (the profile's
    # identity pin); every peer is written, and the pinned
    # endpoint applies to the first — a multi-peer import keeps
    # its later peers' endpoints as written for export fidelity,
    # and connecting one is refused rather than half-driven.
    if len(peers) > 1:
        raise TunnelError(
            "This profile names more than one server peer. Sphinx's "
            "Windows tunnel drives one server per profile in Phase "
            "1, so this profile was not connected — split it into "
            "one profile per server to use it."
        )
    peer = peers[0]
    total_allowed = len(peer.allowed_ips)
    size = (
        ctypes.sizeof(_WireGuardInterface)
        + ctypes.sizeof(_WireGuardPeer)
        + total_allowed * ctypes.sizeof(_WireGuardAllowedIp)
    )
    buffer = ctypes.create_string_buffer(size)
    offset = 0

    iface = _WireGuardInterface.from_buffer(buffer, offset)
    iface.Flags = _INTERFACE_HAS_PRIVATE_KEY | _INTERFACE_REPLACE_PEERS
    iface.ListenPort = getattr(profile, "listen_port", None) or 0
    private_raw = _key_bytes(profile.private_key)
    ctypes.memmove(iface.PrivateKey, private_raw, 32)
    iface.PeersCount = 1
    offset += ctypes.sizeof(_WireGuardInterface)

    peer_s = _WireGuardPeer.from_buffer(buffer, offset)
    peer_s.Flags = _PEER_HAS_PUBLIC_KEY | _PEER_REPLACE_ALLOWED_IPS
    ctypes.memmove(peer_s.PublicKey, _key_bytes(peer.public_key), 32)
    if peer.preshared_key:
        peer_s.Flags |= _PEER_HAS_PRESHARED_KEY
        ctypes.memmove(peer_s.PresharedKey, _key_bytes(peer.preshared_key), 32)
    if peer.persistent_keepalive is not None:
        peer_s.Flags |= _PEER_HAS_PERSISTENT_KEEPALIVE
        peer_s.PersistentKeepalive = int(peer.persistent_keepalive)
    peer_s.Flags |= _PEER_HAS_ENDPOINT
    ip = ipaddress.ip_address(endpoint_ip)
    if ip.version == 4:
        peer_s.Endpoint.Ipv4.sin_family = _AF_INET
        peer_s.Endpoint.Ipv4.sin_port = socket.htons(endpoint_port)
        ctypes.memmove(peer_s.Endpoint.Ipv4.sin_addr, ip.packed, 4)
    else:
        peer_s.Endpoint.Ipv6.sin6_family = _AF_INET6
        peer_s.Endpoint.Ipv6.sin6_port = socket.htons(endpoint_port)
        ctypes.memmove(peer_s.Endpoint.Ipv6.sin6_addr, ip.packed, 16)
    peer_s.AllowedIPsCount = total_allowed
    offset += ctypes.sizeof(_WireGuardPeer)

    for cidr in peer.allowed_ips:
        entry = _WireGuardAllowedIp.from_buffer(buffer, offset)
        network = ipaddress.ip_network(cidr, strict=False)
        ctypes.memmove(entry.Address, network.network_address.packed,
                       len(network.network_address.packed))
        entry.AddressFamily = _AF_INET if network.version == 4 else _AF_INET6
        entry.Cidr = network.prefixlen
        entry.Flags = 0
        offset += ctypes.sizeof(_WireGuardAllowedIp)
    return buffer.raw


# --- DLL discovery -------------------------------------------------------


def dll_candidates() -> List[Path]:
    """Where the bundled wireguard.dll may live, in order: an
    explicit override, beside the exe (the installer and portable
    layouts), the frozen bundle, the source tree's packaging
    folder, and finally the plain DLL search path (empty name)."""
    candidates: List[Path] = []
    override = os.environ.get("SPHINX_WIREGUARD_DLL")
    if override:
        candidates.append(Path(override))
    if getattr(sys, "frozen", False):
        candidates.append(Path(sys.executable).resolve().parent / _WIREGUARD_DLL_NAME)
        meipass = getattr(sys, "_MEIPASS", None)
        if meipass:
            candidates.append(Path(meipass) / "sphinx_win" / "tunnel" / _WIREGUARD_DLL_NAME)
    here = Path(__file__).resolve()
    candidates.append(
        here.parents[3] / "packaging" / "third-party" / _WIREGUARD_DLL_NAME
    )
    return candidates


def find_wireguard_dll() -> Optional[Path]:
    for candidate in dll_candidates():
        if candidate.is_file():
            return candidate
    return None


def _run_powershell(script: str) -> None:
    completed = subprocess.run(
        [
            "powershell.exe",
            "-NoProfile",
            "-NonInteractive",
            "-ExecutionPolicy",
            "Bypass",
            "-Command",
            script,
        ],
        capture_output=True,
        text=True,
        timeout=60,
    )
    if completed.returncode != 0:
        raise TunnelError(
            "Windows networking failed: "
            + (completed.stderr or completed.stdout).strip()
        )


class WindowsTunnelManager:
    """TunnelManager backed by the bundled WireGuardNT DLL."""

    def __init__(self, dll_path: Optional[Path] = None):
        self._dll_path = Path(dll_path) if dll_path is not None else find_wireguard_dll()
        self._dll = None
        self._adapter = None

    # --- Contract -------------------------------------------------

    def is_elevated(self) -> bool:
        if sys.platform != "win32":
            return False
        try:
            return bool(ctypes.windll.shell32.IsUserAnAdmin())
        except Exception:
            return False

    def availability(self) -> Tuple[bool, str]:
        if sys.platform != "win32":
            return False, "VPN mode's Windows tunnel only runs on Windows."
        if self._dll_path is None or not Path(self._dll_path).is_file():
            return (
                False,
                "The bundled WireGuard component (wireguard.dll) "
                "was not found beside Sphinx, so VPN mode cannot "
                "start. Reinstall Sphinx to restore it.",
            )
        return True, ""

    def generate_keypair(self):
        return _generate_keypair()

    # --- Lifecycle --------------------------------------------------

    def _load(self):
        if self._dll is not None:
            return self._dll
        ok, reason = self.availability()
        if not ok:
            raise TunnelUnavailable(reason)
        dll = ctypes.WinDLL(str(self._dll_path))
        dll.WireGuardCreateAdapter.restype = ctypes.c_void_p
        dll.WireGuardCreateAdapter.argtypes = [
            ctypes.c_wchar_p, ctypes.c_wchar_p, ctypes.c_void_p,
        ]
        dll.WireGuardSetConfiguration.restype = ctypes.c_bool
        dll.WireGuardSetConfiguration.argtypes = [
            ctypes.c_void_p, ctypes.c_void_p, ctypes.c_uint32,
        ]
        dll.WireGuardSetAdapterState.restype = ctypes.c_bool
        dll.WireGuardSetAdapterState.argtypes = [ctypes.c_void_p, ctypes.c_int]
        dll.WireGuardGetConfiguration.restype = ctypes.c_bool
        dll.WireGuardGetConfiguration.argtypes = [
            ctypes.c_void_p, ctypes.c_void_p, ctypes.POINTER(ctypes.c_uint32),
        ]
        dll.WireGuardCloseAdapter.restype = None
        dll.WireGuardCloseAdapter.argtypes = [ctypes.c_void_p]
        self._dll = dll
        return dll

    def up(self, profile, *, endpoint_ip: str, endpoint_port: int) -> None:
        if not self.is_elevated():
            raise TunnelNotElevated(
                "Bringing a VPN tunnel up needs administrator "
                "rights (it creates a network adapter and changes "
                "routes). Nothing was changed."
            )
        dll = self._load()
        # No requested GUID: the GUID byte order is its own world,
        # and passing none lets Windows assign one — the adapter is
        # Sphinx's by name and by this process's handle, which
        # cannot mis-assign its identity.
        adapter = dll.WireGuardCreateAdapter(
            ADAPTER_NAME, ADAPTER_TUNNEL_TYPE, None
        )
        if not adapter:
            raise TunnelError(
                "Windows refused to create the Sphinx network "
                f"adapter (error {ctypes.get_last_error()}). The "
                "tunnel was not started."
            )
        self._adapter = adapter
        try:
            blob = build_config_blob(
                profile, endpoint_ip=endpoint_ip, endpoint_port=endpoint_port
            )
            buffer = ctypes.create_string_buffer(blob, len(blob))
            if not dll.WireGuardSetConfiguration(
                adapter, buffer, len(blob)
            ):
                raise TunnelError(
                    "WireGuard refused the profile's configuration; "
                    "the tunnel was not started."
                )
            if not dll.WireGuardSetAdapterState(adapter, _ADAPTER_STATE_UP):
                raise TunnelError(
                    "The Sphinx adapter could not be set up; the "
                    "tunnel was not started."
                )
            self._program_addresses_and_routes(
                profile, endpoint_ip=endpoint_ip
            )
        except Exception:
            # A half-programmed tunnel must not linger as an
            # unowned adapter — but its routes, if any were added,
            # die with the adapter when it closes.
            self.down()
            raise

    def _program_addresses_and_routes(self, profile, *, endpoint_ip: str) -> None:
        """Assign the tunnel addresses and the profile's routes to
        the Sphinx adapter. The endpoint itself gets a host route
        through the pre-tunnel gateway only implicitly: Windows
        routes the endpoint via the physical adapter because the
        tunnel adapter's routes are the profile's AllowedIPs and
        the endpoint is reached on the underlay — for a full
        tunnel (0.0.0.0/0) the WireGuardNT driver handles the
        endpoint binding; if a real machine proves a host route
        is needed, that proof — not a guess — adds it here."""
        commands = []
        alias = ADAPTER_NAME.replace("'", "''")
        for address in profile.client_addresses:
            iface = ipaddress.ip_interface(address)
            commands.append(
                f"New-NetIPAddress -InterfaceAlias '{alias}' "
                f"-IPAddress {iface.ip} -PrefixLength {iface.network.prefixlen} "
                "-ErrorAction Stop | Out-Null"
            )
        peer = profile.peers[0]
        for cidr in peer.allowed_ips:
            commands.append(
                f"if (-not (Get-NetRoute -InterfaceAlias '{alias}' "
                f"-DestinationPrefix {cidr} -ErrorAction SilentlyContinue)) {{ "
                f"New-NetRoute -InterfaceAlias '{alias}' "
                f"-DestinationPrefix {cidr} -ErrorAction Stop | Out-Null }}"
            )
        if getattr(profile, "mtu", None):
            commands.append(
                f"Set-NetIPInterface -InterfaceAlias '{alias}' "
                f"-NlMtuBytes {int(profile.mtu)} -ErrorAction SilentlyContinue"
            )
        if commands:
            _run_powershell("\n".join(commands))

    def down(self) -> None:
        if self._dll is None or self._adapter is None:
            # Try to open an adapter a previous (crashed) run of
            # this same process-shape left behind? No: a leftover
            # adapter from another owner is surfaced by the mode
            # model, never silently taken over (TUNNEL-SPEC).
            self._adapter = None
            return
        try:
            self._dll.WireGuardSetAdapterState(
                self._adapter, _ADAPTER_STATE_DOWN
            )
        except Exception:
            pass
        try:
            self._dll.WireGuardCloseAdapter(self._adapter)
        finally:
            self._adapter = None

    def status(self) -> TunnelStatus:
        if self._dll is None or self._adapter is None:
            return TunnelStatus(adapter_up=False)
        size = ctypes.c_uint32(0)
        self._dll.WireGuardGetConfiguration(self._adapter, None, size)
        if size.value < ctypes.sizeof(_WireGuardInterface) + ctypes.sizeof(
            _WireGuardPeer
        ):
            return TunnelStatus(adapter_up=True)
        buffer = ctypes.create_string_buffer(size.value)
        if not self._dll.WireGuardGetConfiguration(
            self._adapter, buffer, size
        ):
            return TunnelStatus(adapter_up=True)
        peer = _WireGuardPeer.from_buffer(
            buffer, ctypes.sizeof(_WireGuardInterface)
        )
        handshake_ms = None
        if peer.LastHandshake:
            handshake_ms = (
                int(peer.LastHandshake) // 10_000
            ) - _WINDOWS_EPOCH_OFFSET_MS
        return TunnelStatus(
            adapter_up=True,
            latest_handshake_ms=handshake_ms,
            rx_bytes=int(peer.RxBytes),
            tx_bytes=int(peer.TxBytes),
        )
