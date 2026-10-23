"""OpenVPN guard on a FAKE openvpn executable/runner: engage /
proof / teardown / prerm interplay, missing-binary refusal, and
the kill-switch honesty level (Phase 2)."""
import time

from sphinx_deb.core.tunnel import parse_config
from sphinx_deb.core.tunnelstore import TunnelStore
from sphinx_deb.tunnel.guard import (
    MISSING_OPENVPN_MESSAGE,
    OPENVPN_INTERFACE,
    TunnelGuard,
    TunnelState,
)

OPENVPN = (
    "client\ndev tun\nproto udp\nremote vpn-node.example.org 1194\n"
    "resolv-retry infinite\nnobind\npersist-key\npersist-tun\n"
    "up /tmp/evil.sh\nscript-security 2\n"
    "<ca>\n-----BEGIN CERTIFICATE-----\nEXAMPLE-CERTIFICATE-NOT-REAL\n"
    "-----END CERTIFICATE-----\n</ca>\n"
)


class FakeOpenVPNRunner:
    """The edition's fake pattern, extended for openvpn: a fake
    process (pid 4242) whose liveness and tun interface the test
    controls."""

    def __init__(self, *, binary=True, start_ok=True, iface=True):
        self.binary = binary
        self.start_ok = start_ok
        self.iface = iface
        self.alive = False
        self.pid = None
        self.calls = []
        self.argv_seen = []
        self.order = []

    def is_root(self):
        return True

    def which(self, name):
        if name == "openvpn":
            return "/usr/sbin/openvpn" if self.binary else None
        return f"/usr/bin/{name}"

    def run(self, argv, input_text=None):
        self.calls.append(list(argv))
        return 0, "", ""

    def resolve(self, host):
        return ["203.0.113.7"]

    def default_routes(self):
        return "default via 192.168.1.1 dev eth0"

    def wg_show(self, interface):
        return None

    def interface_exists(self, interface):
        if interface == OPENVPN_INTERFACE:
            return self.alive and self.iface
        return False

    def probe_dns(self, server):
        return True

    def openvpn_start(self, argv, log_path=None):
        self.argv_seen.append(list(argv))
        self.order.append("ovpn-start")
        if not self.start_ok:
            return None, "fake start failure"
        self.alive = True
        self.pid = 4242
        return 4242, ""

    def openvpn_alive(self, pid):
        return self.alive and pid == 4242

    def openvpn_stop(self, pid):
        self.order.append("ovpn-stop")
        self.alive = False
        return True


def _guard(tmp_path, runner, **kw):
    store = TunnelStore(tmp_path / "state")
    return TunnelGuard(runner, store, tmp_path / "run", **kw), store


def _profile():
    profile = parse_config(OPENVPN)
    profile.name = "Node"
    return profile


def test_engage_proves_sanitizes_and_records(tmp_path):
    runner = FakeOpenVPNRunner()
    guard, store = _guard(tmp_path, runner)
    result = guard.engage(_profile())
    assert result.ok, result.message
    assert "removed" in result.message and "up" in result.message
    record = store.load_session()
    assert record["protocol"] == "openvpn"
    assert record["intent"] is True
    assert record["dns_behavior"] == "pull-filter-reject-pushed-dns"
    assert "up" in record["removed_directives"]
    assert "script-security" in record["removed_directives"]
    rendered = (tmp_path / "run" / "tunnel" / "sphinx-openvpn.conf").read_text()
    assert "evil.sh" not in rendered
    assert "script-security" not in rendered
    assert 'pull-filter ignore "dhcp-option DNS"' in rendered
    assert guard.status().connected is True
    assert guard.detect_state() == TunnelState.ENGAGED


def test_missing_binary_is_an_honest_refusal_naming_remedy(tmp_path):
    runner = FakeOpenVPNRunner(binary=False)
    guard, store = _guard(tmp_path, runner)
    result = guard.engage(_profile())
    assert not result.ok
    assert result.message == MISSING_OPENVPN_MESSAGE
    assert "sudo apt install openvpn" in result.message
    assert "Recommends" in result.message
    assert store.load_session() is None
    assert runner.argv_seen == []


def test_failed_start_proves_nothing_and_keeps_leftover(tmp_path):
    runner = FakeOpenVPNRunner(start_ok=False)
    guard, store = _guard(tmp_path, runner)
    result = guard.engage(_profile())
    assert not result.ok
    assert store.load_session()["state"] == "leftover"
    assert guard.status().connected is False


def test_no_interface_means_no_connected_claim(tmp_path):
    runner = FakeOpenVPNRunner(iface=False)
    guard, store = _guard(tmp_path, runner)
    result = guard.engage(_profile())
    assert not result.ok
    assert "did not prove" in result.message
    assert guard.status().connected is False


def test_disengage_order_is_tunnel_then_dns_and_exact(tmp_path):
    runner = FakeOpenVPNRunner()

    class DnsResult:
        ok = True
        message = "restored"

    def dns_restore():
        runner.order.append("dns-restore")
        return DnsResult()

    guard, store = _guard(tmp_path, runner, dns_restore=dns_restore)
    assert guard.engage(_profile()).ok
    runner.order.clear()
    result = guard.disengage()
    assert result.ok, result.message
    assert runner.order == ["ovpn-stop", "dns-restore"]
    assert store.load_session() is None


def test_unexpected_exit_is_leftover_with_kill_switch_wording(tmp_path):
    runner = FakeOpenVPNRunner()
    guard, store = _guard(tmp_path, runner)
    assert guard.engage(_profile()).ok
    runner.alive = False  # the process died on its own
    status = guard.status()
    assert status.state == TunnelState.LEFTOVER
    assert status.connected is False
    # Plain-words level: DNS not re-pointed, traffic NOT blackholed.
    assert "does NOT silently re-point DNS" in status.kill_switch
    assert "NOT" in status.kill_switch and "blackhole" in status.kill_switch


def test_teardown_for_removal_stops_openvpn(tmp_path):
    runner = FakeOpenVPNRunner()
    guard, store = _guard(tmp_path, runner)
    assert guard.engage(_profile()).ok
    result = guard.teardown_for_removal()
    assert result.ok
    assert runner.alive is False
    assert store.load_session() is None


def test_teardown_for_removal_fails_loudly_when_stop_fails(tmp_path):
    runner = FakeOpenVPNRunner()
    runner.openvpn_stop = lambda pid: False  # cannot be stopped
    guard, store = _guard(tmp_path, runner)
    assert guard.engage(_profile()).ok
    result = guard.teardown_for_removal()
    assert not result.ok
    assert store.load_session() is not None  # record kept for prerm to stop on
