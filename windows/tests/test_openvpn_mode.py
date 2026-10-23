"""The OpenVPN mode model (Phase 2) over the fake OpenVPN engine:
sanitized handoff, establishment proof (never from spawn), pushed
DNS honesty in both VPN modes, the unexpected-exit kill-switch
posture, teardown through the record (incl. the --restore-vpn
headless path), and the not-installed honest state — all without
a machine."""
import pytest

from sphinx_win.app.controller import SphinxController, SphinxMode, StartError
from sphinx_win.core.store import Store
from sphinx_win.dnsmgmt.fake import FakeDnsManager
from sphinx_win.tunnelmgmt.base import TunnelNotElevated
from sphinx_win.tunnelmgmt.fake import FakeTunnelManager
from sphinx_win.tunnelmgmt.openvpn_fake import FakeOpenVpnManager

from test_vpn_mode import ADAPTERS, WG_HOME, FakeServer

OPENVPN_EVIL = (
    "client\ndev tun\nproto udp\nremote vpn-node.example.org 1194\n"
    "resolv-retry infinite\nnobind\npersist-key\n"
    "script-security 2\nup /tmp/evil-up.sh\ndown /tmp/evil-down.sh\n"
    "route-up /tmp/evil-route.sh\nplugin /tmp/evil.dll auth\n"
    "management 127.0.0.1 7505\nauth-user-pass /tmp/creds.txt\n"
    "log-append /tmp/ovpn.log\n"
    "<ca>\n-----BEGIN CERTIFICATE-----\nEXAMPLE-CERTIFICATE-NOT-REAL\n"
    "-----END CERTIFICATE-----\n</ca>\n"
)

PUSHED = ["10.8.0.53", "10.8.0.54"]


def make_controller(tmp_path, openvpn=None, tunnel=None, **kw):
    store = Store(tmp_path / "data")
    manager = FakeDnsManager(ADAPTERS, elevated=True)
    controller = SphinxController(
        store,
        manager,
        tmp_path / "data",
        server_factory=lambda e: FakeServer(e),
        tunnel_manager=tunnel if tunnel is not None else FakeTunnelManager(),
        openvpn_manager=openvpn if openvpn is not None else FakeOpenVpnManager(pushed_dns=PUSHED),
        resolver=lambda host: "198.51.100.23",
        handshake_wait_s=kw.get("handshake_wait_s", 0.5),
        vpn_forwarder_factory=kw.get("vpn_forwarder_factory"),
    )
    try:
        controller.tunnel_store.import_text(OPENVPN_EVIL, name="Node")
    except Exception:
        pass
    return controller, manager


class TestConnect:
    def test_connect_hands_the_engine_a_sanitized_copy_only(self, tmp_path):
        ovpn = FakeOpenVpnManager(pushed_dns=PUSHED)
        controller, _ = make_controller(tmp_path, openvpn=ovpn)
        message = controller.connect_vpn("Node", with_blocker=False)
        assert controller.current_mode() is SphinxMode.VPN_ONLY
        assert controller.vpn_status().connected
        # The engine was handed the SANITIZED working copy…
        handed = ovpn.sanitized_config
        assert handed is not None
        for token in ("/tmp/evil", "/tmp/creds.txt", "script-security",
                      "management", "plugin", "log-append"):
            assert token not in handed, token
        assert "remote vpn-node.example.org 1194" in handed
        # …the removals were surfaced, not silent…
        assert "removed" in message
        assert "up" in message and "plugin" in message
        # …and the STORED profile is untouched by sanitizing.
        stored = controller.tunnel_store.export_text("Node")
        assert "up /tmp/evil-up.sh" in stored

    def test_no_proof_is_never_connected(self, tmp_path):
        # The client process runs but never proves establishment:
        # the status is the blocked kill-switch state, not
        # "connected" from a spawn.
        ovpn = FakeOpenVpnManager(pushed_dns=[], established=False)
        controller, _ = make_controller(tmp_path, openvpn=ovpn)
        controller.connect_vpn("Node", with_blocker=False)
        status = controller.vpn_status()
        assert not status.connected
        assert status.blocked
        assert "traffic is blocked" in status.message

    def test_unelevated_connect_touches_nothing(self, tmp_path):
        ovpn = FakeOpenVpnManager(elevated=False)
        controller, manager = make_controller(tmp_path, openvpn=ovpn)
        with pytest.raises(TunnelNotElevated):
            controller.connect_vpn("Node", with_blocker=False)
        assert ovpn.up_calls == []
        assert manager.get_dns("Wi-Fi", "IPv4") == ["192.168.1.1"]
        assert controller.tunnel_store.load_state() is None


class TestPushedDns:
    def test_vpn_only_accepts_pushed_dns_under_the_tunnel_record(
        self, tmp_path
    ):
        controller, manager = make_controller(tmp_path)
        message = controller.connect_vpn("Node", with_blocker=False)
        # DNS points at the server's pushed set (tunnel record)…
        assert manager.get_dns("Wi-Fi", "IPv4") == PUSHED
        # …the audited DNS backup was never created or touched…
        assert controller.guard.load_backup() is None
        assert not (tmp_path / "data" / "dns-backup.json").exists()
        # …and the status says whose DNS is in force.
        assert "DNS in force: the server's own" in message
        assert "10.8.0.53" in message
        controller.disconnect_vpn()
        # Restored exactly, record retired.
        assert manager.get_dns("Wi-Fi", "IPv4") == ["192.168.1.1"]
        assert controller.tunnel_store.load_state() is None

    def test_vpn_plus_blocker_brain_in_front_pushed_upstream(self, tmp_path):
        captured = {}

        def factory(dns_servers):
            captured["dns"] = list(dns_servers)
            return lambda q: None

        controller, manager = make_controller(
            tmp_path, vpn_forwarder_factory=factory
        )
        message = controller.connect_vpn("Node", with_blocker=True)
        assert controller.current_mode() is SphinxMode.VPN_BLOCKER
        # The brain's upstreams became the pushed set…
        assert captured["dns"] == PUSHED
        # …system DNS is the loopback filter under the guard…
        assert manager.get_dns("Wi-Fi", "IPv4") == ["127.0.0.1"]
        state = controller.tunnel_store.load_state()
        assert state.dns_originals == []
        assert state.protocol == "openvpn"
        # …and the status names both facts.
        assert "Ad blocking on" in message
        assert "pushed DNS" in message
        controller.disconnect_vpn()
        assert manager.get_dns("Wi-Fi", "IPv4") == ["192.168.1.1"]

    def test_no_pushed_dns_is_stated_not_invented(self, tmp_path):
        ovpn = FakeOpenVpnManager(pushed_dns=[])
        controller, manager = make_controller(tmp_path, openvpn=ovpn)
        message = controller.connect_vpn("Node", with_blocker=False)
        assert "pushed no DNS" in message
        # Nothing was pointed anywhere: the machine's DNS is as it was.
        assert manager.get_dns("Wi-Fi", "IPv4") == ["192.168.1.1"]
        state = controller.tunnel_store.load_state()
        assert state.dns_originals == []


class TestUnexpectedExit:
    def test_child_death_holds_the_dns_posture_and_announces(self, tmp_path):
        ovpn = FakeOpenVpnManager(pushed_dns=PUSHED)
        controller, manager = make_controller(tmp_path, openvpn=ovpn)
        controller.connect_vpn("Node", with_blocker=False)
        assert manager.get_dns("Wi-Fi", "IPv4") == PUSHED
        ovpn.simulate_unexpected_exit()
        # The status/monitor path notices on its next read…
        status = controller.vpn_status()
        assert status.blocked and not status.connected
        assert "exited unexpectedly" in status.message
        assert "Reconnect" in status.message
        assert "disconnect intentionally" in status.message
        # …and DNS was NOT silently restored to a direct
        # connection as if nothing happened: it stays exactly
        # where Sphinx placed it for the tunnel.
        assert manager.get_dns("Wi-Fi", "IPv4") == PUSHED
        # The intentional disconnect — the user's own choice —
        # is what restores, exactly, through the ordinary path.
        controller.disconnect_vpn()
        assert manager.get_dns("Wi-Fi", "IPv4") == ["192.168.1.1"]
        assert controller.tunnel_store.load_state() is None

    def test_child_death_in_vpn_plus_blocker_keeps_the_filter_posture(
        self, tmp_path
    ):
        ovpn = FakeOpenVpnManager(pushed_dns=PUSHED)
        controller, manager = make_controller(tmp_path, openvpn=ovpn)
        controller.connect_vpn("Node", with_blocker=True)
        ovpn.simulate_unexpected_exit()
        status = controller.vpn_status()
        assert status.blocked
        assert "exited unexpectedly" in status.message
        # DNS stays with Sphinx: the loopback filter, still
        # running, its upstreams still the pushed set.
        assert manager.get_dns("Wi-Fi", "IPv4") == ["127.0.0.1"]
        assert controller.running

    def test_reconnect_after_unexpected_exit(self, tmp_path):
        ovpn = FakeOpenVpnManager(pushed_dns=PUSHED)
        controller, _ = make_controller(tmp_path, openvpn=ovpn)
        controller.connect_vpn("Node", with_blocker=False)
        ovpn.simulate_unexpected_exit()
        assert controller.vpn_status().blocked
        message = controller.reconnect_vpn()
        assert controller.vpn_status().connected
        assert "VPN on — Node" in message


class TestCrossProtocol:
    def test_one_tunnel_at_a_time_across_protocols(self, tmp_path):
        wg = FakeTunnelManager()
        controller, _ = make_controller(tmp_path, tunnel=wg)
        controller.tunnel_store.import_text(WG_HOME)
        controller.connect_vpn("Home Server", with_blocker=False)
        downs = wg.down_calls
        controller.connect_vpn("Node", with_blocker=False)
        assert wg.down_calls > downs
        assert controller.vpn_status().profile_name == "Node"
        controller.disconnect_vpn()
        assert controller.current_mode() is SphinxMode.OFF


class TestNotInstalled:
    def test_missing_openvpn_is_an_honest_named_state(self, tmp_path):
        ovpn = FakeOpenVpnManager(installed=False)
        controller, manager = make_controller(tmp_path, openvpn=ovpn)
        with pytest.raises(StartError) as refused:
            controller.connect_vpn("Node", with_blocker=False)
        message = str(refused.value)
        assert "OpenVPN isn't installed" in message
        assert "openvpn.net" in message  # the remedy's official source
        assert "does not bundle" in message
        assert ovpn.up_calls == []
        assert manager.get_dns("Wi-Fi", "IPv4") == ["192.168.1.1"]
        assert controller.tunnel_store.load_state() is None


class TestQuestionsNamesOnOpenVpn:
    def test_unlisted_resolves_via_pushed_upstream_listed_sinkholes(
        self, tmp_path
    ):
        """The owner's criterion on the OpenVPN + Blocker path:
        the filter questions names only — an UNLISTED name
        resolves normally through the pushed upstream and its
        traffic passes; a LISTED name sinkholes locally and never
        reaches the upstream."""
        from dnsutil import build_query, build_response_for

        forwarded = []

        def factory(dns_servers):
            assert dns_servers == PUSHED

            def fwd(query):
                forwarded.append(query)
                return build_response_for(query)

            return fwd

        controller, _ = make_controller(
            tmp_path, vpn_forwarder_factory=factory
        )
        controller.store.save_custom_block_entries(["ads.example.com"])
        controller.reload_lists()
        controller.connect_vpn("Node", with_blocker=True)

        answer = controller.engine.handle_query(
            build_query("tracker-lookalike.example.com")
        )
        assert answer is not None and answer[-4:] == bytes([93, 184, 216, 34])
        assert len(forwarded) == 1

        blocked = controller.engine.handle_query(
            build_query("ads.example.com")
        )
        assert blocked[-4:] == bytes([0, 0, 0, 0])
        assert len(forwarded) == 1  # listed names never go upstream


class TestLeftover:
    def test_leftover_openvpn_disconnect_ends_the_recorded_pid(
        self, tmp_path
    ):
        ovpn = FakeOpenVpnManager(pushed_dns=PUSHED)
        controller, _ = make_controller(tmp_path, openvpn=ovpn)
        controller.connect_vpn("Node", with_blocker=False)
        # A new controller over the same folder (the host died):
        # the record is a leftover, and disconnecting it ends the
        # recorded child pid rather than leaving an orphan.
        ovpn2 = FakeOpenVpnManager(pushed_dns=PUSHED)
        controller2, manager2 = make_controller(tmp_path, openvpn=ovpn2)
        assert controller2.tunnel_leftover()
        controller2.disconnect_vpn()
        assert ovpn2.terminated_pids == [4242]
        assert controller2.tunnel_store.load_state() is None
        assert manager2.get_dns("Wi-Fi", "IPv4") == ["192.168.1.1"]


class TestUninstallTeardown:
    def test_restore_vpn_tears_an_openvpn_session_down(self, tmp_path):
        """--restore-vpn over an OpenVPN record: the recorded
        child pid is terminated through the OpenVPN manager, the
        record's DNS originals are restored and verified, and
        the record retires — the same discipline as WireGuard's,
        one protocol over."""
        from sphinx_win.app.main import restore_vpn_main
        from sphinx_win.core.tunnelstore import TunnelState, TunnelStore
        from sphinx_win.dnsmgmt.base import AdapterDns

        data = tmp_path / "data"
        store = TunnelStore(data)
        store.save_state(
            TunnelState(
                profile_name="Node",
                intent=True,
                protocol="openvpn",
                openvpn_pid=4242,
                dns_originals=[
                    {
                        "interface_alias": "Wi-Fi",
                        "family": "IPv4",
                        "servers": ["192.168.1.1"],
                    }
                ],
                dns_applied=PUSHED,
            )
        )
        manager = FakeDnsManager(
            [AdapterDns("Wi-Fi", "IPv4", PUSHED)], elevated=True
        )

        class RecordingOvpn:
            down_called = False
            terminated = []

            def down(self):
                RecordingOvpn.down_called = True

            def terminate_pid(self, pid):
                RecordingOvpn.terminated.append(pid)
                return True

        class _Wg:
            def down(self):
                pass

        messages = []
        assert (
            restore_vpn_main(
                data,
                tunnel_manager_factory=_Wg,
                openvpn_manager_factory=RecordingOvpn,
                dns_manager_factory=lambda: manager,
                out=messages.append,
            )
            == 0
        )
        assert RecordingOvpn.down_called
        assert RecordingOvpn.terminated == [4242]
        assert manager.get_dns("Wi-Fi", "IPv4") == ["192.168.1.1"]
        assert store.load_state() is None
