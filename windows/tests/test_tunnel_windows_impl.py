"""The WireGuardNT backend's pure parts, testable anywhere: the
wireguard.h struct layout, the configuration blob builder (with
the pinned endpoint inside it), the DLL search, and the bundled
DLL's integrity pin. The adapter/route/handshake path itself is
proven only on a real Windows machine — a named release gate."""
import ctypes
import hashlib
import ipaddress
import socket
from pathlib import Path

import pytest

from sphinx_win.core.tunnel import parse_profile
from sphinx_win.tunnelmgmt import windows_impl as wi

WG = (
    "# Sphinx profile: Home Server\n[Interface]\n"
    "PrivateKey = hI9byVWLK8639iOPJ8Z3ej9sp4rhqOdnHQ3pfp0N35s=\n"
    "Address = 10.8.0.2/32\nDNS = 10.8.0.1\n\n[Peer]\n"
    "PublicKey = q6GQz9IBykkuC3C+kX7l8w7SU9s6yP0Vq8UurgHsiFU=\n"
    "Endpoint = vpn.example.com:51820\nAllowedIPs = 0.0.0.0/0, 10.0.0.0/8\n"
    "PersistentKeepalive = 25\n"
)

THIRD_PARTY = (
    Path(__file__).resolve().parent.parent
    / "packaging"
    / "third-party"
)


class TestStructLayout:
    """Sizes from wireguard.h's ALIGNED(8) structures."""

    def test_sizes(self):
        assert ctypes.sizeof(wi._WireGuardInterface) == 80
        assert ctypes.sizeof(wi._WireGuardPeer) == 136
        assert ctypes.sizeof(wi._WireGuardAllowedIp) == 24

    def test_field_offsets(self):
        # The header's natural member layout (see windows_impl):
        # keys are BYTE arrays, so they pack at 6 and 38; the
        # ALIGNED(8) shows up as the struct strides (80/136/24),
        # asserted in test_sizes.
        assert wi._WireGuardInterface.PrivateKey.offset == 6
        assert wi._WireGuardInterface.PublicKey.offset == 38
        assert wi._WireGuardInterface.PeersCount.offset == 72
        assert wi._WireGuardPeer.Endpoint.offset == 76
        assert wi._WireGuardPeer.LastHandshake.offset == 120
        assert wi._WireGuardAllowedIp.Cidr.offset == 18


class TestConfigBlob:
    def test_blob_carries_keys_pinned_endpoint_and_allowed_ips(self):
        profile = parse_profile(WG)
        blob = wi.build_config_blob(
            profile, endpoint_ip="198.51.100.23", endpoint_port=51820
        )
        expected = (
            ctypes.sizeof(wi._WireGuardInterface)
            + ctypes.sizeof(wi._WireGuardPeer)
            + 2 * ctypes.sizeof(wi._WireGuardAllowedIp)
        )
        assert len(blob) == expected
        buffer = ctypes.create_string_buffer(blob, len(blob))
        iface = wi._WireGuardInterface.from_buffer(buffer, 0)
        assert iface.PeersCount == 1
        peer = wi._WireGuardPeer.from_buffer(
            buffer, ctypes.sizeof(wi._WireGuardInterface)
        )
        import base64

        assert bytes(peer.PublicKey) == base64.b64decode(
            "q6GQz9IBykkuC3C+kX7l8w7SU9s6yP0Vq8UurgHsiFU="
        )
        assert peer.PersistentKeepalive == 25
        # The endpoint inside the blob is the PIN (an address),
        # never the profile's hostname.
        assert peer.Endpoint.Ipv4.sin_family == 2
        assert socket.ntohs(peer.Endpoint.Ipv4.sin_port) == 51820
        assert bytes(peer.Endpoint.Ipv4.sin_addr) == ipaddress.ip_address(
            "198.51.100.23"
        ).packed
        first = wi._WireGuardAllowedIp.from_buffer(
            buffer,
            ctypes.sizeof(wi._WireGuardInterface)
            + ctypes.sizeof(wi._WireGuardPeer),
        )
        assert first.Cidr == 0
        assert first.AddressFamily == 2

    def test_multi_peer_profile_refused_not_half_driven(self):
        profile = parse_profile(
            "# Sphinx profile: Two Doors\n[Interface]\n"
            "PrivateKey = hI9byVWLK8639iOPJ8Z3ej9sp4rhqOdnHQ3pfp0N35s=\n"
            "Address = 10.8.0.2/32\n\n[Peer]\n"
            "PublicKey = q6GQz9IBykkuC3C+kX7l8w7SU9s6yP0Vq8UurgHsiFU=\n"
            "Endpoint = one.example.com:51820\nAllowedIPs = 10.1.0.0/16\n\n"
            "[Peer]\n"
            "PublicKey = ukI3DodjYWN46wnWXHUkkshvzC03Go/6V1V7M7ofwj8=\n"
            "Endpoint = two.example.com:51820\nAllowedIPs = 10.2.0.0/16\n"
        )
        with pytest.raises(wi.TunnelError):
            wi.build_config_blob(
                profile, endpoint_ip="198.51.100.23", endpoint_port=51820
            )


class TestBundledComponent:
    def test_bundled_dll_matches_the_official_distribution_pin(self):
        # PROVENANCE.md: wireguard-nt-1.0.zip's bin/amd64/wireguard.dll,
        # byte-for-byte. A swapped or rebuilt DLL fails here.
        data = (THIRD_PARTY / "wireguard.dll").read_bytes()
        assert (
            hashlib.sha256(data).hexdigest()
            == "40add3d0b47bee347fcad0f59a0a68ca3d98fb4f7aa90cc4e8ff76086219eca7"
        )

    def test_bundled_license_is_the_prebuilt_binaries_license(self):
        text = (THIRD_PARTY / "WireGuardNT-LICENSE.txt").read_text(
            encoding="utf-8"
        )
        assert "Prebuilt Binaries License" in text
        assert "wireguard.dll" in text
        assert "Permitted API" in text

    def test_dll_search_finds_the_source_tree_copy(self):
        found = wi.find_wireguard_dll()
        assert found is not None and found.name == "wireguard.dll"

    def test_availability_off_windows_is_an_honest_no(self):
        manager = wi.WindowsTunnelManager()
        ok, reason = manager.availability()
        if wi.sys.platform != "win32":
            assert not ok and reason
        assert manager.status().adapter_up is False
