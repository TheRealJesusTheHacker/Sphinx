"""The tunnel guard on a fake runner: resolve-before-engage and
pinning, save-first, prove-or-roll-back, tunnel-then-DNS teardown,
keypairs from `wg` only (TUNNEL-SPEC kill-switch + guard rules)."""
import time

import pytest

from sphinx_deb.core.tunnel import parse_config
from sphinx_deb.core.tunnelstore import TunnelStore
from sphinx_deb.tunnel.guard import (
    MISSING_TOOLS_MESSAGE,
    TunnelGuard,
    TunnelState,
)

CLIENT_KEY = "hI9byVWLK8639iOPJ8Z3ej9sp4rhqOdnHQ3pfp0N35s="
SERVER_KEY = "q6GQz9IBykkuC3C+kX7l8w7SU9s6yP0Vq8UurgHsiFU="

WG = (
    "# Sphinx profile: Home Server\n"
    "[Interface]\n"
    f"PrivateKey = {CLIENT_KEY}\n"
    "Address = 10.8.0.2/32\n"
    "DNS = 10.8.0.1\n"
    "\n"
    "[Peer]\n"
    f"PublicKey = {SERVER_KEY}\n"
    "Endpoint = vpn.example.com:51820\n"
    "AllowedIPs = 0.0.0.0/0\n"
)

OPENVPN = (
    "client\ndev tun\nproto udp\nremote vpn-node.example.org 1194\n"
    "resolv-retry infinite\nnobind\npersist-key\npersist-tun\n"
)


class FakeRunner:
    def __init__(self, *, tools=True, resolve_map=None, probe=True, handshake_age=5):
        self.tools = tools
        self.resolve_map = resolve_map if resolve_map is not None else {
            "vpn.example.com": ["203.0.113.7"]
        }
        self.probe = probe
        self.handshake_age = handshake_age
        self.up = False
        self.calls = []
        self.order = []

    def is_root(self):
        return True

    def which(self, name):
        return f"/usr/bin/{name}" if self.tools else None

    def run(self, argv, input_text=None):
        self.calls.append(list(argv))
        if argv[:2] == ["wg", "genkey"]:
            return 0, CLIENT_KEY + "\n", ""
        if argv[:2] == ["wg", "pubkey"]:
            assert input_text and CLIENT_KEY in input_text
            return 0, SERVER_KEY + "\n", ""
        if argv[:3] == ["wg", "show", "sphinx0"] and len(argv) == 4 and argv[3] == "latest-handshakes":
            if not self.up:
                return 1, "", "no such interface"
            epoch = int(time.time()) - self.handshake_age
            return 0, f"{SERVER_KEY}\t{epoch}\n", ""
        if argv[:2] == ["wg-quick", "up"]:
            self.up = True
            self.order.append("tunnel-up")
            return 0, "", ""
        if argv[:2] == ["wg-quick", "down"]:
            self.up = False
            self.order.append("tunnel-down")
            return 0, "", ""
        return 0, "", ""

    def resolve(self, host):
        return list(self.resolve_map.get(host, []))

    def default_routes(self):
        return "default via 192.168.1.1 dev eth0"

    def wg_show(self, interface):
        return "interface: sphinx0\n" if self.up else None

    def interface_exists(self, interface):
        return self.up

    def probe_dns(self, server):
        return self.probe


def _guard(tmp_path, runner, **kw):
    store = TunnelStore(tmp_path / "state")
    return TunnelGuard(runner, store, tmp_path / "run", **kw), store


def test_engage_proves_resolves_first_and_pins(tmp_path):
    runner = FakeRunner()
    guard, store = _guard(tmp_path, runner)
    result = guard.engage(parse_config(WG))
    assert result.ok, result.message
    record = store.load_session()
    assert record["intent"] is True
    assert record["pinned_endpoint"] == "203.0.113.7:51820"
    assert record["pre_tunnel"]["default_routes"].startswith("default via")
    rendered = (tmp_path / "run" / "tunnel" / "sphinx0.conf").read_text()
    assert "Endpoint = 203.0.113.7:51820" in rendered  # pinned
    assert "DNS =" not in rendered  # Sphinx manages DNS itself
    assert guard.detect_state() == TunnelState.ENGAGED
    assert guard.status().connected is True


def test_engage_refuses_when_the_name_does_not_resolve(tmp_path):
    runner = FakeRunner(resolve_map={})
    guard, store = _guard(tmp_path, runner)
    result = guard.engage(parse_config(WG))
    assert not result.ok
    assert "could not be resolved" in result.message
    assert not any(c[:1] == ["wg-quick"] for c in runner.calls)
    assert store.load_session() is None


def test_missing_tools_refusal_names_the_remedy(tmp_path):
    runner = FakeRunner(tools=False)
    guard, _store = _guard(tmp_path, runner)
    result = guard.engage(parse_config(WG))
    assert not result.ok
    assert result.message == MISSING_TOOLS_MESSAGE
    assert "sudo apt install wireguard-tools" in result.message


def test_openvpn_profile_is_refused_at_connect_with_the_reason(tmp_path):
    runner = FakeRunner()
    guard, _store = _guard(tmp_path, runner)
    result = guard.engage(parse_config(OPENVPN))
    assert not result.ok
    assert "Phase 2" in result.message and "OpenVPN" in result.message
    assert not runner.calls  # nothing was even attempted


def test_stale_handshake_rolls_back_and_keeps_the_record(tmp_path):
    runner = FakeRunner(handshake_age=100_000)
    guard, store = _guard(tmp_path, runner)
    result = guard.engage(parse_config(WG))
    assert not result.ok
    assert "did not prove" in result.message
    assert runner.order == ["tunnel-up", "tunnel-down"]  # rolled back
    record = store.load_session()
    assert record is not None and record["state"] == "leftover"
    assert record["intent"] is False
    assert guard.status().connected is False  # never claimed from intent


def test_failed_probe_rolls_back(tmp_path):
    runner = FakeRunner(probe=False)
    guard, store = _guard(tmp_path, runner)
    result = guard.engage(parse_config(WG))
    assert not result.ok
    assert runner.order == ["tunnel-up", "tunnel-down"]
    assert store.load_session()["state"] == "leftover"


def test_disconnect_order_is_tunnel_down_then_dns_restore(tmp_path):
    runner = FakeRunner()

    class DnsResult:
        ok = True
        message = "restored"

    def dns_restore():
        runner.order.append("dns-restore")
        return DnsResult()

    guard, store = _guard(tmp_path, runner, dns_restore=dns_restore)
    assert guard.engage(parse_config(WG)).ok
    runner.order.clear()
    result = guard.disengage()
    assert result.ok, result.message
    assert runner.order == ["tunnel-down", "dns-restore"]
    assert store.load_session() is None


def test_second_connect_disconnects_the_first_through_the_stop_path(tmp_path):
    runner = FakeRunner()
    guard, store = _guard(tmp_path, runner)
    assert guard.engage(parse_config(WG)).ok
    other = parse_config(WG.replace("Home Server", "Other").replace(
        "vpn.example.com", "203.0.113.7"))
    result = guard.engage(other)
    assert result.ok, result.message
    assert runner.order.count("tunnel-down") == 1
    assert store.load_session()["profile"] == "Other"


def test_record_alone_never_reads_as_connected(tmp_path):
    runner = FakeRunner()
    guard, store = _guard(tmp_path, runner)
    store.save_session({"version": 1, "state": "engaged", "profile": "Home Server",
                        "mode": "vpn", "intent": True})
    status = guard.status()
    assert status.state == TunnelState.LEFTOVER
    assert status.connected is False


def test_keypair_comes_from_wg_never_from_python(tmp_path):
    runner = FakeRunner()
    guard, _store = _guard(tmp_path, runner)
    private, public = guard.generate_keypair()
    assert private == CLIENT_KEY and public == SERVER_KEY
    assert ["wg", "genkey"] in runner.calls
    assert ["wg", "pubkey"] in runner.calls


def test_keypair_without_tools_is_an_honest_refusal(tmp_path):
    runner = FakeRunner(tools=False)
    guard, _store = _guard(tmp_path, runner)
    with pytest.raises(RuntimeError) as exc:
        guard.generate_keypair()
    assert "wireguard-tools" in str(exc.value)
