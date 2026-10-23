"""The TUNNEL-SPEC mode model over the fake tunnel manager:
Off / Blocker only / VPN only / VPN + Blocker, endpoint pinning,
one tunnel at a time, the kill switch, the ordinary stop path
back, and the Phase 1 OpenVPN refusal — all without a machine."""
import pytest

from sphinx_win.app.controller import SphinxController, SphinxMode, StartError
from sphinx_win.core.store import Store
from sphinx_win.dnsmgmt.base import AdapterDns
from sphinx_win.dnsmgmt.fake import FakeDnsManager
from sphinx_win.tunnelmgmt.base import TunnelNotElevated
from sphinx_win.tunnelmgmt.fake import FakeTunnelManager

ADAPTERS = [
    AdapterDns("Wi-Fi", "IPv4", ["192.168.1.1"]),
    AdapterDns("Wi-Fi", "IPv6", []),
]

WG_HOME = (
    "# Sphinx profile: Home Server\n[Interface]\n"
    "PrivateKey = hI9byVWLK8639iOPJ8Z3ej9sp4rhqOdnHQ3pfp0N35s=\n"
    "Address = 10.8.0.2/32\nDNS = 10.8.0.1\n\n[Peer]\n"
    "PublicKey = q6GQz9IBykkuC3C+kX7l8w7SU9s6yP0Vq8UurgHsiFU=\n"
    "Endpoint = vpn.example.com:51820\nAllowedIPs = 0.0.0.0/0\n"
)
WG_OFFICE = (
    "# Sphinx profile: Office Only\n[Interface]\n"
    "PrivateKey = hI9byVWLK8639iOPJ8Z3ej9sp4rhqOdnHQ3pfp0N35s=\n"
    "Address = 10.9.0.2/32\n\n[Peer]\n"
    "PublicKey = q6GQz9IBykkuC3C+kX7l8w7SU9s6yP0Vq8UurgHsiFU=\n"
    "Endpoint = 203.0.113.7:51820\nAllowedIPs = 10.0.0.0/8, 192.168.0.0/16\n"
)
OPENVPN = (
    "client\ndev tun\nproto udp\nremote vpn-node.example.org 1194\n"
    "resolv-retry infinite\nnobind\npersist-key\npersist-tun\n<ca>\n"
    "-----BEGIN CERTIFICATE-----\nEXAMPLE-CERTIFICATE-NOT-REAL\n"
    "-----END CERTIFICATE-----\n</ca>\n"
)


class FakeServer:
    def __init__(self, engine):
        self.engine = engine
        self.stopped = False

    def start(self):
        return [("127.0.0.1", 53), ("::1", 53)]

    def answers_on(self, address, timeout=2.0):
        return True

    def stop(self):
        self.stopped = True


def make_controller(tmp_path, tunnel=None, resolver=None, **kw):
    store = Store(tmp_path / "data")
    manager = FakeDnsManager(ADAPTERS, elevated=True)
    tunnel = tunnel if tunnel is not None else FakeTunnelManager()
    controller = SphinxController(
        store,
        manager,
        tmp_path / "data",
        server_factory=lambda e: FakeServer(e),
        tunnel_manager=tunnel,
        resolver=resolver or (lambda host: "198.51.100.23"),
        handshake_wait_s=kw.get("handshake_wait_s", 0.5),
    )
    try:
        controller.tunnel_store.import_text(WG_HOME)
    except Exception:
        pass  # a second controller over the same folder (restart tests)
    return controller, manager, tunnel


class TestModes:
    def test_off_to_vpn_only_and_back(self, tmp_path):
        controller, manager, tunnel = make_controller(tmp_path)
        assert controller.current_mode() is SphinxMode.OFF
        message = controller.connect_vpn("Home Server", with_blocker=False)
        assert controller.current_mode() is SphinxMode.VPN_ONLY
        assert controller.vpn_status().connected
        assert "VPN on — Home Server" in message
        # VPN-only says DNS is unfiltered, where the status lives.
        assert "Ads are not blocked in this mode" in message
        controller.disconnect_vpn()
        assert controller.current_mode() is SphinxMode.OFF
        assert not tunnel.adapter_up

    def test_vpn_plus_blocker_and_back_to_off(self, tmp_path):
        controller, _, _ = make_controller(tmp_path)
        message = controller.connect_vpn("Home Server", with_blocker=True)
        assert controller.current_mode() is SphinxMode.VPN_BLOCKER
        assert controller.running  # the blocker leg is up
        assert "Ad blocking on" in message
        controller.disconnect_vpn()
        # Pre-VPN mode was Off: disconnect returns there, through
        # the ordinary stop path (blocker stopped, DNS restored).
        assert controller.current_mode() is SphinxMode.OFF
        assert not controller.running

    def test_disconnect_returns_to_blocker_only(self, tmp_path):
        controller, _, _ = make_controller(tmp_path)
        controller.start()
        assert controller.current_mode() is SphinxMode.BLOCKER_ONLY
        controller.connect_vpn("Home Server", with_blocker=True)
        controller.disconnect_vpn()
        assert controller.current_mode() is SphinxMode.BLOCKER_ONLY
        assert controller.running

    def test_one_tunnel_at_a_time(self, tmp_path):
        controller, _, tunnel = make_controller(tmp_path)
        controller.tunnel_store.import_text(WG_OFFICE)
        controller.connect_vpn("Home Server", with_blocker=False)
        downs_before = tunnel.down_calls
        controller.connect_vpn("Office Only", with_blocker=False)
        assert tunnel.down_calls > downs_before  # first went down first
        assert controller.vpn_status().profile_name == "Office Only"

    def test_vpn_only_from_blocker_stops_and_restores_the_blocker(
        self, tmp_path
    ):
        # VPN ONLY means the brain is not in the path: entering it
        # from Blocker only must stop the blocker (never leave it
        # filtering under a status that says "unfiltered"), and
        # disconnect must return to Blocker only.
        controller, manager, _ = make_controller(tmp_path)
        controller.start()
        controller.connect_vpn("Home Server", with_blocker=False)
        assert controller.current_mode() is SphinxMode.VPN_ONLY
        assert not controller.running  # the brain really is out
        assert manager.get_dns("Wi-Fi", "IPv4") == ["10.8.0.1"]
        assert controller.guard.load_backup() is None
        controller.disconnect_vpn()
        assert controller.current_mode() is SphinxMode.BLOCKER_ONLY
        assert controller.running
        assert manager.get_dns("Wi-Fi", "IPv4") == ["127.0.0.1"]

    def test_failed_up_rolls_back_to_the_pre_vpn_mode(self, tmp_path):
        from sphinx_win.tunnelmgmt.base import TunnelError

        controller, manager, tunnel = make_controller(tmp_path)
        tunnel.fail_on_up = TunnelError("boom")
        with pytest.raises(StartError):
            controller.connect_vpn("Home Server", with_blocker=True)
        # Nothing half-connected: no tunnel, no blocker started
        # for the occasion left running, no record, DNS untouched.
        assert not tunnel.adapter_up
        assert not controller.running
        assert controller.tunnel_store.load_state() is None
        assert manager.get_dns("Wi-Fi", "IPv4") == ["192.168.1.1"]
        assert controller.current_mode() is SphinxMode.OFF

    def test_split_tunnel_scope_is_some(self, tmp_path):
        controller, _, _ = make_controller(tmp_path)
        controller.tunnel_store.import_text(WG_OFFICE)
        profile = controller.tunnel_store.get_profile("Office Only")
        assert profile.scope == "some"


class TestPinning:
    def test_endpoint_resolved_before_engage_and_pinned(self, tmp_path):
        order = []

        def resolver(host):
            order.append(("resolve", host, tunnel.adapter_up))
            return "198.51.100.23"

        controller, _, tunnel = make_controller(tmp_path, resolver=resolver)
        controller.connect_vpn("Home Server", with_blocker=False)
        # Resolved while the tunnel was still down (the pre-tunnel
        # resolver), and the manager was handed the PIN — the
        # address, never the hostname.
        assert order == [("resolve", "vpn.example.com", False)]
        assert tunnel.pinned == ("198.51.100.23", 51820)
        state = controller.tunnel_store.load_state()
        assert state.pinned_endpoint == "198.51.100.23:51820"

    def test_unresolvable_endpoint_connects_nothing(self, tmp_path):
        def resolver(host):
            raise OSError("name or service not known")

        controller, manager, tunnel = make_controller(tmp_path, resolver=resolver)
        with pytest.raises(StartError):
            controller.connect_vpn("Home Server", with_blocker=False)
        assert not tunnel.adapter_up
        assert tunnel.up_calls == []
        assert manager.get_dns("Wi-Fi", "IPv4") == ["192.168.1.1"]


class TestVpnOnlyDns:
    def test_dns_via_tunnel_record_never_the_dns_backup(self, tmp_path):
        controller, manager, _ = make_controller(tmp_path)
        controller.connect_vpn("Home Server", with_blocker=False)
        # DNS points at the profile's server (reached via the
        # tunnel) as tunnel-record state…
        assert manager.get_dns("Wi-Fi", "IPv4") == ["10.8.0.1"]
        # …and the audited DNS backup was never created or touched.
        assert controller.guard.load_backup() is None
        assert not (tmp_path / "data" / "dns-backup.json").exists()
        controller.disconnect_vpn()
        # Restored exactly, and the record retired.
        assert manager.get_dns("Wi-Fi", "IPv4") == ["192.168.1.1"]
        assert controller.tunnel_store.load_state() is None

    def test_vpn_plus_blocker_uses_the_guard_not_the_tunnel_record(
        self, tmp_path
    ):
        controller, manager, _ = make_controller(tmp_path)
        controller.connect_vpn("Home Server", with_blocker=True)
        # The blocker path: system DNS at the loopback filter,
        # under the ordinary DNS backup…
        assert manager.get_dns("Wi-Fi", "IPv4") == ["127.0.0.1"]
        assert controller.guard.load_backup() is not None
        # …and the tunnel record holds no DNS originals of its own.
        state = controller.tunnel_store.load_state()
        assert state.dns_originals == []
        controller.disconnect_vpn()
        assert manager.get_dns("Wi-Fi", "IPv4") == ["192.168.1.1"]


class TestKillSwitch:
    def test_stale_handshake_is_blocked_never_connected(self, tmp_path):
        tunnel = FakeTunnelManager(handshake_age_ms=10_000_000)
        controller, _, _ = make_controller(tmp_path, tunnel=tunnel)
        message = controller.connect_vpn("Home Server", with_blocker=False)
        status = controller.vpn_status()
        assert not status.connected
        assert status.blocked
        assert "traffic is blocked, not going around the tunnel" in message
        # The choices are named in the status itself.
        assert "Reconnect" in status.message
        assert "disconnect" in status.message

    def test_dropped_tunnel_blackholes_covered_traffic(self, tmp_path):
        controller, _, tunnel = make_controller(tmp_path)
        controller.connect_vpn("Home Server", with_blocker=False)
        assert tunnel.send_packet("203.0.113.99") == "tunnel"
        tunnel.drop_tunnel()
        assert controller.vpn_status().blocked
        # Covered traffic blocks — it does NOT fall back to direct.
        assert tunnel.send_packet("203.0.113.99") == "blocked"
        controller.disconnect_vpn()
        assert tunnel.send_packet("203.0.113.99") == "direct"

    def test_reconnect_after_drop(self, tmp_path):
        controller, _, tunnel = make_controller(tmp_path)
        controller.connect_vpn("Home Server", with_blocker=False)
        tunnel.drop_tunnel()
        assert controller.vpn_status().blocked
        message = controller.reconnect_vpn()
        assert controller.vpn_status().connected
        assert "VPN on — Home Server" in message


class TestRefusals:
    def test_openvpn_without_an_installed_client_is_an_honest_state(
        self, tmp_path
    ):
        # Phase 2: OpenVPN profiles CONNECT through the user's
        # installed OpenVPN program. This controller was built
        # with no OpenVPN engine (the not-installed machine), so
        # connecting names that state and the remedy — never a
        # silent failure, never a bundled copy, nothing engaged.
        # (Phase 1's connect refusal was superseded by Phase 2;
        # the full OpenVPN mode model is in test_openvpn_mode.py.)
        controller, _, tunnel = make_controller(tmp_path)
        controller.tunnel_store.import_text(OPENVPN, name="Node")
        with pytest.raises(StartError) as refused:
            controller.connect_vpn("Node", with_blocker=False)
        assert "OpenVPN isn't installed" in str(refused.value)
        assert "openvpn.net" in str(refused.value)
        assert not tunnel.adapter_up
        assert tunnel.up_calls == []
        assert controller.tunnel_store.load_state() is None

    def test_unelevated_connect_touches_nothing(self, tmp_path):
        tunnel = FakeTunnelManager(elevated=False)
        controller, manager, _ = make_controller(tmp_path, tunnel=tunnel)
        with pytest.raises(TunnelNotElevated):
            controller.connect_vpn("Home Server", with_blocker=False)
        assert tunnel.up_calls == []
        assert manager.get_dns("Wi-Fi", "IPv4") == ["192.168.1.1"]
        assert controller.tunnel_store.load_state() is None

    def test_unknown_profile_refused(self, tmp_path):
        controller, _, _ = make_controller(tmp_path)
        with pytest.raises(StartError):
            controller.connect_vpn("Nope", with_blocker=False)


class TestLeftover:
    def test_record_without_a_live_tunnel_is_a_leftover(self, tmp_path):
        controller, _, _ = make_controller(tmp_path)
        controller.connect_vpn("Home Server", with_blocker=False)
        # A new controller over the same data folder (a restart):
        # the record is there, the tunnel is not — surfaced, never
        # silently taken over or dropped.
        controller2, _, _ = make_controller(tmp_path)
        assert controller2.tunnel_leftover()
        status = controller2.vpn_status()
        assert status.leftover
        assert not status.connected
        # Disconnect clears the leftover through the ordinary path
        # (including restoring the DNS the record holds).
        controller2.disconnect_vpn()
        assert controller2.tunnel_store.load_state() is None
