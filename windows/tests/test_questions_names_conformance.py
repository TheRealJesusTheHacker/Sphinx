"""CONFORMANCE — TUNNEL-SPEC, "The filter questions names; it
does not block traffic" + "Sphinx must never be the reason an
unlisted name fails" (owner's standing criteria, 2026-10-23).

The named proofs:

- ``test_unlisted_name_resolves_and_traffic_passes_blocker_path``
- ``test_unlisted_name_resolves_and_traffic_passes_vpn_plus_blocker_path``
- ``test_blocked_name_sinkholes_fast_even_when_upstream_is_dead``
- ``test_unlisted_name_survives_first_upstream_failure_via_fallback``

Levels, stated honestly (per the spec's conformance rule):
the blocker path is proven at the filter-engine level plus a
real local DNS exchange through forward_query's fallback chain
(real UDP sockets to local fake upstreams — the production
forwarder, unmodified). The VPN + Blocker path is proven at the
mode-model level: the real controller + real filter engine over
the Fake tunnel manager, whose ``send_packet`` is the data-plane
model of the routes the real backend programs (see
tunnelmgmt/fake.py) — real-machine packet proof is the named
Windows release gate, not something a unit suite can claim.
"""
import socket
import threading
import time
from functools import partial

from sphinx_win.app.controller import SphinxController
from sphinx_win.core.blocklist import Allowlist, Blocklist, FilterLists
from sphinx_win.core.forwarder import forward_query
from sphinx_win.core.server import FilterEngine
from sphinx_win.core.store import Store
from sphinx_win.dnsmgmt.base import AdapterDns
from sphinx_win.dnsmgmt.fake import FakeDnsManager
from sphinx_win.tunnelmgmt.fake import FakeTunnelManager
from dnsutil import build_query, build_response_for

LISTED = "ads.example.com"
UNLISTED_LOOKALIKE = "tracker-lookalike.example.com"  # resembles, unlisted


def _engine(forwarder):
    lists = FilterLists(Blocklist({LISTED}), Allowlist([]))
    return FilterEngine(lambda: lists, forwarder=forwarder)


def _answer_ip(answer: bytes) -> bytes:
    return answer[-4:]


# --- Blocker path -------------------------------------------------------


def test_unlisted_name_resolves_and_traffic_passes_blocker_path():
    """Blocker path: an unlisted name — even one that merely
    LOOKS tracker-adjacent — resolves normally through the
    forwarder, and the filter installs no drop anywhere: its
    only action was the DNS decision. (At this level 'traffic
    passes' is proven by the filter's shape: handle_query is the
    whole surface, it returns the upstream's real answer for the
    unlisted name, and there is no other traffic path in the
    blocker to block — the DATA-plane half of this proof is the
    VPN test below, over the tunnel model's send_packet.)"""
    forwarded = []

    def stub_forwarder(query):
        forwarded.append(query)
        return build_response_for(query)

    engine = _engine(stub_forwarder)
    answer = engine.handle_query(build_query(UNLISTED_LOOKALIKE))
    assert answer is not None
    assert _answer_ip(answer) == bytes([93, 184, 216, 34])  # real answer
    assert len(forwarded) == 1  # it went upstream, unmodified path

    listed_answer = engine.handle_query(build_query(LISTED))
    assert listed_answer is not None
    assert _answer_ip(listed_answer) == bytes([0, 0, 0, 0])  # sinkhole
    assert len(forwarded) == 1  # the listed name never went upstream


def test_blocked_name_sinkholes_fast_even_when_upstream_is_dead():
    """A blocked name fails FAST and clean: the sinkhole is built
    locally, so even a forwarder that would hang forever (a dead
    tunnel upstream) cannot turn a refusal into a timeout — the
    forwarder is never consulted for a listed name."""

    def hanging_forwarder(query):
        time.sleep(30)
        return None

    engine = _engine(hanging_forwarder)
    started = time.monotonic()
    answer = engine.handle_query(build_query(LISTED))
    elapsed = time.monotonic() - started
    assert answer is not None
    assert _answer_ip(answer) == bytes([0, 0, 0, 0])
    assert elapsed < 1.0


# --- The unlisted fallback duty ------------------------------------------


class _Upstream(threading.Thread):
    """A local fake upstream; ``answers=False`` models a dead one
    (receives and never replies)."""

    def __init__(self, address, port, answers=True):
        super().__init__(daemon=True)
        self.sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        self.sock.bind((address, port))
        self.sock.settimeout(5)
        self.answers = answers

    def run(self):
        try:
            data, addr = self.sock.recvfrom(65535)
            if self.answers:
                self.sock.connect(addr)
                self.sock.send(build_response_for(data))
        except OSError:
            pass
        finally:
            self.sock.close()


def _free_port():
    with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as s:
        s.bind(("127.0.0.1", 0))
        return s.getsockname()[1]


def test_unlisted_name_survives_first_upstream_failure_via_fallback():
    """Sphinx must never be the reason an unlisted name fails:
    the production forwarder exhausts its fallback discipline —
    first resolver dead (127.0.0.2, silent), the fallback
    (127.0.0.1) answers, and the unlisted name resolves. The
    failure of one upstream is never swallowed into silence
    while another honestly answers."""
    port = _free_port()
    dead = _Upstream("127.0.0.2", port, answers=False)
    good = _Upstream("127.0.0.1", port, answers=True)
    dead.start()
    good.start()
    engine = _engine(
        partial(
            forward_query,
            resolvers=("127.0.0.2", "127.0.0.1"),
            port=port,
            timeout=0.5,
        )
    )
    answer = engine.handle_query(build_query(UNLISTED_LOOKALIKE))
    assert answer is not None
    assert _answer_ip(answer) == bytes([93, 184, 216, 34])


def test_unlisted_failure_is_the_upstreams_genuine_failure_only():
    """When EVERY upstream genuinely fails, the query goes
    unanswered — that is the upstreams' failure, not a Sphinx
    decision — and the engine surfaces it as no-answer, never as
    a sinkhole (a Sphinx-made failure dressed as a block)."""
    port = _free_port()  # nothing listens: every resolver fails
    engine = _engine(
        partial(
            forward_query,
            resolvers=("127.0.0.1", "127.0.0.1"),
            port=port,
            timeout=0.3,
        )
    )
    assert engine.handle_query(build_query(UNLISTED_LOOKALIKE)) is None
    # And the counters say what happened: allowed at the decision.
    assert engine.allowed_count == 1
    assert engine.blocked_count == 0


# --- VPN + Blocker path (mode-model level) -----------------------------

WG_HOME = (
    "# Sphinx profile: Home Server\n[Interface]\n"
    "PrivateKey = hI9byVWLK8639iOPJ8Z3ej9sp4rhqOdnHQ3pfp0N35s=\n"
    "Address = 10.8.0.2/32\nDNS = 10.8.0.1\n\n[Peer]\n"
    "PublicKey = q6GQz9IBykkuC3C+kX7l8w7SU9s6yP0Vq8UurgHsiFU=\n"
    "Endpoint = vpn.example.com:51820\nAllowedIPs = 0.0.0.0/0\n"
)


class _FakeServer:
    def __init__(self, engine):
        self.engine = engine

    def start(self):
        return [("127.0.0.1", 53), ("::1", 53)]

    def answers_on(self, address, timeout=2.0):
        return True

    def stop(self):
        pass


def test_unlisted_name_resolves_and_traffic_passes_vpn_plus_blocker_path(
    tmp_path,
):
    """VPN + Blocker path, at the mode-model level (see the
    module docstring for the level statement): connected over
    the Fake tunnel manager, with the profile's DNS upstream
    stubbed at the forwarder factory —
    - an UNLISTED name resolves through the tunnel upstream, and
    - its traffic is carried by the tunnel (the model's
      send_packet says "tunnel", not "blocked", not dropped),
    - a LISTED name still sinkholes locally,
    - and when the tunnel drops, the ONLY new blocking is the
      announced kill-switch state — status names it, with the
      disconnect choice, and disconnect restores passage."""
    store = Store(tmp_path / "data")
    manager = FakeDnsManager(
        [AdapterDns("Wi-Fi", "IPv4", ["192.168.1.1"])], elevated=True
    )
    tunnel = FakeTunnelManager()
    forwarded = []

    def stub_vpn_forwarder(dns_servers):
        assert dns_servers == ["10.8.0.1"]  # the profile's DNS, via tunnel

        def fwd(query):
            forwarded.append(query)
            return build_response_for(query)

        return fwd

    controller = SphinxController(
        store,
        manager,
        tmp_path / "data",
        server_factory=lambda e: _FakeServer(e),
        tunnel_manager=tunnel,
        resolver=lambda host: "198.51.100.23",
        vpn_forwarder_factory=stub_vpn_forwarder,
        handshake_wait_s=0.5,
    )
    controller.tunnel_store.import_text(WG_HOME)
    # The filter's lists for this proof: LISTED is blocked,
    # everything else is the unlisted path.
    controller.store.save_custom_block_entries([LISTED])
    controller.reload_lists()

    message = controller.connect_vpn("Home Server", with_blocker=True)
    assert "Ad blocking on" in message

    answer = controller.engine.handle_query(build_query(UNLISTED_LOOKALIKE))
    assert answer is not None
    assert _answer_ip(answer) == bytes([93, 184, 216, 34])
    assert len(forwarded) == 1
    # Its traffic passes — carried by the tunnel, untouched.
    assert tunnel.send_packet("93.184.216.34") == "tunnel"

    blocked = controller.engine.handle_query(build_query(LISTED))
    assert _answer_ip(blocked) == bytes([0, 0, 0, 0])
    assert len(forwarded) == 1  # listed names never reach the upstream

    # The tunnel dies: the kill switch is the only blocking, and
    # it announces itself — never a silent full-block.
    tunnel.drop_tunnel()
    status = controller.vpn_status()
    assert status.blocked and not status.connected
    assert "traffic is blocked, not going around the tunnel" in status.message
    assert tunnel.send_packet("93.184.216.34") == "blocked"

    # The one-tap intentional disconnect ends the blocked state
    # and returns to the pre-VPN mode; traffic is direct again.
    controller.disconnect_vpn()
    assert tunnel.send_packet("93.184.216.34") == "direct"
    assert not controller.vpn_status().blocked
