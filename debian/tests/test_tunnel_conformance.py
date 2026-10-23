"""CONFORMANCE for TUNNEL-SPEC, "The filter questions names; it
does not block traffic" (the owner's standing criterion):

- an UNLISTED name resolves AND its traffic passes with the
  filter on — on the blocker path, and on the VPN+Blocker path;
- a tracker-adjacent-looking but unlisted name passes (listing
  is the whole test; resemblance is not evidence);
- a listed name is sinkholed FAST and locally — the forwarder is
  never consulted, so there is no stall to make an app look
  offline;
- the unlisted path degrades through the forwarder's fallback
  chain (first upstream fails -> fallback answers), never toward
  silence — TUNNEL-SPEC's unlisted-name principle;
- an internal error is surfaced through the engine's error hook,
  never swallowed silently;
- VPN-only mode forwards unfiltered (the brain is not in the
  path, and the UI says so — here the engine proves the path).
"""
from __future__ import annotations

import socket
import threading

from conftest import requires_udp
from sphinx_deb.core.blocklist import Allowlist, Blocklist, FilterLists
from sphinx_deb.core.dnswire import build_query, parse_query
from sphinx_deb.core.forwarder import forward_query
from sphinx_deb.core.server import FilterEngine
from sphinx_deb.daemon import tunnel_upstreams
from sphinx_deb.core.tunnel import parse_config
from sphinx_deb.core.tunnelstore import TunnelStore

LISTED = "ads.example.com"
UNLISTED = "music.example.com"
TRACKERISH = "metrics.analytics-cdn.example.com"  # unlisted; merely looks the part


def _canned_answer(query: bytes) -> bytes:
    """A believable upstream answer: the query with the QR bit set."""
    answer = bytearray(query)
    answer[2] |= 0x80
    return bytes(answer)


class RecordingForwarder:
    def __init__(self):
        self.queries = []

    def __call__(self, data: bytes):
        self.queries.append(data)
        return _canned_answer(data)


def _engine(forwarder, **kw):
    lists = FilterLists(Blocklist({LISTED}), Allowlist([]))
    return FilterEngine(
        lists_provider=lambda: lists, forwarder=forwarder, **kw
    )


def test_unlisted_name_resolves_and_traffic_passes_blocker_path():
    forwarder = RecordingForwarder()
    engine = _engine(forwarder)
    query = build_query(UNLISTED)
    answer = engine.handle_query(query)
    # Resolves: the upstream's answer comes back, byte for byte.
    assert answer == _canned_answer(query)
    assert parse_query(answer).is_response
    # And passes untouched: the query the upstream saw is the
    # query that was asked — nothing dropped, delayed, or rerouted
    # by the blocker path (the engine is the whole DNS path here,
    # and DNS is the filter's only action).
    assert forwarder.queries == [query]


def test_tracker_adjacent_but_unlisted_name_passes():
    forwarder = RecordingForwarder()
    engine = _engine(forwarder)
    query = build_query(TRACKERISH)
    assert engine.handle_query(query) == _canned_answer(query)
    assert forwarder.queries == [query]


def test_listed_name_is_sinkholed_fast_and_locally():
    forwarder = RecordingForwarder()
    engine = _engine(forwarder)
    answer = engine.handle_query(build_query(LISTED))
    assert answer is not None
    parsed = parse_query(answer)
    assert parsed is not None and parsed.is_response
    assert b"\x00\x00\x00\x00" in answer  # the 0.0.0.0 sinkhole
    # Fast and clean means local: the forwarder was never asked,
    # so nothing waited on any network path for this refusal.
    assert forwarder.queries == []


def test_unlisted_name_resolves_and_traffic_passes_vpn_plus_blocker_path(tmp_path):
    """The VPN+Blocker path, exactly as daemon.py wires it: the
    session record is engaged in vpn+blocker mode, the upstream
    set is the profile's DNS (through the tunnel), the brain is
    in the path — unlisted resolves via the profile DNS, listed
    is sinkholed locally."""
    store = TunnelStore(tmp_path)
    wg = (
        "# Sphinx profile: Home Server\n"
        "[Interface]\n"
        "PrivateKey = hI9byVWLK8639iOPJ8Z3ej9sp4rhqOdnHQ3pfp0N35s=\n"
        "Address = 10.8.0.2/32\n"
        "DNS = 10.8.0.1\n"
        "\n"
        "[Peer]\n"
        "PublicKey = q6GQz9IBykkuC3C+kX7l8w7SU9s6yP0Vq8UurgHsiFU=\n"
        "Endpoint = vpn.example.com:51820\n"
        "AllowedIPs = 0.0.0.0/0\n"
    )
    store.save(parse_config(wg))
    store.save_session(
        {"version": 1, "state": "engaged", "mode": "vpn+blocker",
         "profile": "Home Server", "intent": True}
    )
    # The daemon's upstream choice under this session: the
    # profile's DNS first, the configured upstreams as fallback.
    assert tunnel_upstreams(store, ["1.1.1.1", "9.9.9.9"]) == [
        "10.8.0.1", "1.1.1.1", "9.9.9.9",
    ]
    forwarder = RecordingForwarder()
    session = {"mode": "vpn+blocker"}
    engine = _engine(
        forwarder,
        filter_enabled=lambda: session.get("mode") != "vpn",
    )
    query = build_query(UNLISTED)
    assert engine.handle_query(query) == _canned_answer(query)
    listed_answer = engine.handle_query(build_query(LISTED))
    assert listed_answer is not None and b"\x00\x00\x00\x00" in listed_answer
    assert forwarder.queries == [query]  # listed never left the box


def test_vpn_only_mode_forwards_unfiltered_and_unlogged():
    forwarder = RecordingForwarder()
    engine = _engine(forwarder, filter_enabled=lambda: False)
    # Even a LISTED name passes in VPN-only mode: the brain is
    # not in this path, and the mode says so where it is offered.
    query = build_query(LISTED)
    assert engine.handle_query(query) == _canned_answer(query)
    assert len(engine.query_log) == 0  # the log is a blocker-path record


def test_internal_error_is_surfaced_never_swallowed():
    surfaced = []

    def broken_forwarder(_data):
        raise RuntimeError("upstream socket exploded (fake)")

    engine = _engine(broken_forwarder, on_error=surfaced.append)
    assert engine.handle_query(build_query(UNLISTED)) is None
    assert len(surfaced) == 1
    assert "exploded" in str(surfaced[0])


@requires_udp
def test_unlisted_query_falls_back_when_first_upstream_fails():
    """The forwarder's honest fallback discipline, on real UDP:
    the first resolver (127.0.0.2 — nothing listening) fails, the
    fallback (127.0.0.1) answers, and the unlisted query succeeds.
    First-upstream failure must never become the query's failure
    while a fallback would have answered it."""
    server = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    server.bind(("127.0.0.1", 0))
    port = server.getsockname()[1]

    def responder():
        try:
            data, addr = server.recvfrom(4096)
            server.sendto(_canned_answer(data), addr)
        except OSError:
            pass

    thread = threading.Thread(target=responder, daemon=True)
    thread.start()
    try:
        query = build_query(UNLISTED)
        answer = forward_query(
            query, resolvers=["127.0.0.2", "127.0.0.1"], timeout=1.0, port=port
        )
    finally:
        server.close()
    assert answer is not None
    assert parse_query(answer).is_response
