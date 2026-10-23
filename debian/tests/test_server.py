"""The filter engine + the loopback server: sinkhole decisions,
counting at the decision, bounded concurrency, the liveness proof
that is not counted as traffic, and real UDP/TCP exchanges on a
high loopback port."""
import socket
import threading

import pytest

from conftest import requires_udp
from sphinx_deb.core.blocklist import Allowlist, Blocklist, FilterLists
from sphinx_deb.core.dnswire import build_query, parse_query
from sphinx_deb.core.server import (
    MAX_IN_FLIGHT_QUERIES,
    DnsFilterServer,
    FilterEngine,
)

PORT = 18553


def _lists():
    return FilterLists(
        Blocklist(["ads.example.com"]), Allowlist([])
    )


def _answering_forwarder(query: bytes) -> bytes:
    out = bytearray(query)
    out[2:4] = (0x8000 | 0x0080).to_bytes(2, "big")
    return bytes(out)


def _engine(forwarder=_answering_forwarder):
    return FilterEngine(lists_provider=_lists, forwarder=forwarder)


def test_blocked_names_get_the_sinkhole_and_count_as_blocked():
    engine = _engine()
    response = engine.handle_query(build_query("ads.example.com", query_id=5))
    assert response is not None
    p = parse_query(response)
    assert p is not None and p.is_response and p.id == 5
    assert engine.blocked_count == 1 and engine.allowed_count == 0


def test_allowed_queries_count_at_the_decision_even_if_upstream_fails():
    engine = _engine(forwarder=lambda q: None)
    response = engine.handle_query(build_query("example.com", query_id=6))
    assert response is None  # unanswered — the asker retries
    assert engine.allowed_count == 1 and engine.blocked_count == 0


def test_malformed_and_response_packets_are_dropped_quietly():
    engine = _engine()
    assert engine.handle_query(b"\x00\x01") is None
    assert engine.handle_query(_answering_forwarder(build_query("example.com"))) is None
    assert engine.blocked_count == 0 and engine.allowed_count == 0


@pytest.fixture()
def server():
    engine = _engine()
    srv = DnsFilterServer(engine, port=PORT)
    bound = srv.start()
    assert ("127.0.0.1", PORT) in bound
    yield srv
    srv.stop()


def _udp_exchange(packet: bytes, address=("127.0.0.1", PORT)) -> bytes:
    family = socket.AF_INET6 if ":" in address[0] else socket.AF_INET
    with socket.socket(family, socket.SOCK_DGRAM) as sock:
        sock.settimeout(2.0)
        sock.connect(address)
        sock.send(packet)
        data, _ = sock.recvfrom(65535)
        return data


@requires_udp
def test_udp_blocked_query_is_sinkholed(server):
    response = _udp_exchange(build_query("ads.example.com", query_id=11))
    parsed = parse_query(response)
    assert parsed is not None and parsed.id == 11 and parsed.is_response
    assert server.engine.blocked_count == 1


def test_tcp_blocked_query_is_sinkholed(server):
    packet = build_query("ads.example.com", query_id=12)
    with socket.create_connection(("127.0.0.1", PORT), timeout=2.0) as conn:
        conn.sendall(len(packet).to_bytes(2, "big") + packet)
        header = conn.recv(2)
        length = int.from_bytes(header, "big")
        data = b""
        while len(data) < length:
            data += conn.recv(length - len(data))
    parsed = parse_query(data)
    assert parsed is not None and parsed.id == 12


@requires_udp
def test_liveness_proof_answers_and_is_not_counted(server):
    assert server.answers_on("127.0.0.1")
    assert server.engine.blocked_count == 0
    assert server.engine.allowed_count == 0
    assert len(server.engine.query_log) == 0


def test_concurrency_budget_is_bounded():
    assert MAX_IN_FLIGHT_QUERIES == 64


@requires_udp
def test_many_queries_in_parallel_all_get_answers(server):
    results = []

    def ask(i):
        results.append(
            _udp_exchange(build_query("ads.example.com", query_id=100 + i))
        )

    threads = [threading.Thread(target=ask, args=(i,)) for i in range(16)]
    for t in threads:
        t.start()
    for t in threads:
        t.join()
    assert len(results) == 16
    assert server.engine.blocked_count == 16


def test_proof_timeout_exceeds_the_forwarders_worst_case():
    # Sweep #4 (W-6 parity): the proof queries an allowed name, so
    # it only passes when the upstream round trip returns in time.
    # The forwarder's worst case is one full timeout per resolver;
    # the Debian port still carried the old 2-second default, which
    # could fail a healthy filter on a slow-upstream machine.
    import inspect

    from sphinx_deb.core.forwarder import UPSTREAM_RESOLVERS, UPSTREAM_TIMEOUT_S
    from sphinx_deb.core.server import PROOF_TIMEOUT_S

    default = inspect.signature(DnsFilterServer.answers_on).parameters["timeout"].default
    assert default == PROOF_TIMEOUT_S
    assert default > len(UPSTREAM_RESOLVERS) * UPSTREAM_TIMEOUT_S


@requires_udp
def test_answers_on_survives_a_slow_upstream():
    # The live half: an upstream that answers correctly but slowly
    # (past the old 2-second proof timeout) must still prove.
    import time

    def slow_forward(query: bytes) -> bytes:
        time.sleep(3.0)
        return _answering_forwarder(query)

    engine = _engine(forwarder=slow_forward)
    srv = DnsFilterServer(engine, port=18559)
    bound = srv.start()
    assert ("127.0.0.1", 18559) in bound
    try:
        assert srv.answers_on("127.0.0.1")  # default timeout
    finally:
        srv.stop()
