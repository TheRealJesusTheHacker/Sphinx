"""The filter engine: decisions, counters, the memory-only log, and
a live loopback socket round trip."""
import socket
import struct
import threading

import pytest

from sphinx_win.core.blocklist import Allowlist, Blocklist, FilterLists
from sphinx_win.core.server import DnsFilterServer, FilterEngine
from dnsutil import build_query, build_response_for


def _loopback_sendto_permitted() -> bool:
    """The repo's build sandbox intermittently blocks unconnected
    UDP sendto() to ephemeral ports (EPERM) — an environment rule,
    not product behavior (replies on the listening socket are the
    canonical DNS server shape, and CI is unrestricted). Probe once
    and skip the live-socket test where the sandbox forbids it."""
    try:
        srv = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        srv.bind(("127.0.0.1", 0))
        port = srv.getsockname()[1]
        srv.settimeout(2)

        def serve():
            try:
                data, addr = srv.recvfrom(1024)
                srv.sendto(b"pong", addr)
            except OSError:
                pass

        threading.Thread(target=serve, daemon=True).start()
        with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as c:
            c.settimeout(2)
            c.connect(("127.0.0.1", port))
            c.send(b"ping")
            return c.recvfrom(1024)[0] == b"pong"
    except OSError:
        return False
    finally:
        try:
            srv.close()
        except Exception:
            pass


requires_udp_replies = pytest.mark.skipif(
    not _loopback_sendto_permitted(),
    reason="build sandbox blocks unconnected UDP sendto replies",
)


def make_engine(forwarder=None, log_enabled=True):
    lists = FilterLists(
        Blocklist.from_lines(["ads.example.com"]),
        Allowlist.from_lines(["good.ads.example.com"]),
    )
    calls = []

    def fake_forward(data):
        calls.append(data)
        return build_response_for(data)

    engine = FilterEngine(
        lambda: lists,
        forwarder=forwarder or fake_forward,
        log_enabled=log_enabled,
        clock_ms=lambda: 1000,
    )
    return engine, calls


class TestEngine:
    def test_blocked_name_gets_sinkhole_not_forward(self):
        engine, calls = make_engine()
        response = engine.handle_query(build_query("ads.example.com"))
        assert response is not None
        assert calls == []
        assert engine.blocked_count == 1
        assert engine.allowed_count == 0
        # Sinkhole: A answer 0.0.0.0
        assert response[-4:] == b"\x00\x00\x00\x00"

    def test_allowed_name_forwarded_unchanged(self):
        engine, calls = make_engine()
        query = build_query("news.example.org")
        response = engine.handle_query(query)
        assert calls == [query]
        assert response == build_response_for(query)
        assert engine.allowed_count == 1

    def test_allowlist_wins_in_engine(self):
        engine, calls = make_engine()
        response = engine.handle_query(build_query("good.ads.example.com"))
        assert response is not None
        assert len(calls) == 1  # forwarded, not sinkholed
        assert engine.allowed_count == 1

    def test_log_records_decisions_in_memory(self):
        engine, _ = make_engine()
        engine.handle_query(build_query("ads.example.com"))
        engine.handle_query(build_query("news.example.org"))
        entries = engine.query_log.snapshot()
        assert [(e.name, e.blocked) for e in entries] == [
            ("news.example.org", False),
            ("ads.example.com", True),
        ]

    def test_log_disabled_records_nothing(self):
        engine, _ = make_engine(log_enabled=False)
        engine.handle_query(build_query("ads.example.com"))
        assert len(engine.query_log) == 0

    def test_malformed_packets_are_dropped_quietly(self):
        engine, calls = make_engine()
        assert engine.handle_query(b"") is None
        assert engine.handle_query(b"\xff" * 40) is None
        assert engine.handle_query(build_query("ads.example.com")[:13]) is None
        assert calls == []

    def test_upstream_failure_leaves_query_unanswered_but_counted(self):
        engine, _ = make_engine(forwarder=lambda data: None)
        assert engine.handle_query(build_query("news.example.org")) is None
        # Counted at the decision (audited Android semantics).
        assert engine.allowed_count == 1


def free_port_pair():
    with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as s:
        s.bind(("127.0.0.1", 0))
        return s.getsockname()[1]


class TestProofHygiene:
    """Windows audit (Phase 1): the server's own liveness proof used
    to be counted and logged as if a user app had asked it."""

    def test_unrecorded_query_answers_without_counting(self):
        engine, _ = make_engine()
        response = engine.handle_query(
            build_query("news.example.org"), record=False
        )
        assert response is not None
        assert engine.allowed_count == 0
        assert len(engine.query_log) == 0

    def test_proof_timeout_exceeds_the_forwarders_worst_case(self):
        # W-6: the proof queries an allowed name, so it only passes
        # when the upstream round trip returns in time. The
        # forwarder's worst case is one full timeout per resolver;
        # a proof timeout at or below that can fail a healthy
        # filter on a slow-upstream machine.
        import inspect

        from sphinx_win.core.forwarder import (
            UPSTREAM_RESOLVERS,
            UPSTREAM_TIMEOUT_S,
        )

        default = inspect.signature(
            DnsFilterServer.answers_on
        ).parameters["timeout"].default
        assert default > len(UPSTREAM_RESOLVERS) * UPSTREAM_TIMEOUT_S

    @requires_udp_replies
    def test_answers_on_survives_a_slow_upstream(self):
        # The live half of W-6: an upstream that answers correctly
        # but slowly (past the old 2-second proof timeout) must
        # still prove — DNS is engaged only after this passes, and
        # a healthy filter must not be failed by upstream latency.
        import time

        def slow_forward(data):
            time.sleep(3.0)
            return build_response_for(data)

        engine, _ = make_engine(forwarder=slow_forward)
        port = free_port_pair()
        server = DnsFilterServer(engine, port=port)
        server.start()
        try:
            assert server.answers_on("127.0.0.1")  # default timeout
        finally:
            server.stop()

    def test_dispatch_consumes_the_proof_token_once(self):
        engine, _ = make_engine()
        server = DnsFilterServer(engine, port=free_port_pair())
        server._proof = (0x1234, "example.com")
        response = server._dispatch(build_query("example.com", qid=0x1234))
        assert response is not None
        assert engine.allowed_count == 0
        assert len(engine.query_log) == 0
        # The token is spent: the same query again is user traffic.
        server._dispatch(build_query("example.com", qid=0x1234))
        assert engine.allowed_count == 1


class TestBoundedConcurrency:
    """Windows audit (Phase 1): the threading servers spawned one
    thread per datagram with no bound, so a flood of slow queries
    grew the process without limit (the twin of the Android
    edition's Phase 3 finding). In-flight work is capped now; this
    flood needs no replies, so it runs even where the sandbox eats
    them."""

    def test_udp_flood_cannot_grow_threads_without_limit(self):
        import time

        def slow_forward(data):
            time.sleep(2.0)
            return build_response_for(data)

        engine, _ = make_engine(forwarder=slow_forward)
        port = free_port_pair()
        server = DnsFilterServer(engine, port=port)
        server.start()
        try:
            base = threading.active_count()
            with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as sock:
                sock.connect(("127.0.0.1", port))
                query = build_query("news.example.org")
                for _ in range(150):
                    try:
                        sock.send(query)
                    except OSError:
                        pass
            time.sleep(0.8)
            grew = threading.active_count() - base
            from sphinx_win.core.server import MAX_IN_FLIGHT_QUERIES

            assert grew <= MAX_IN_FLIGHT_QUERIES + 10
        finally:
            server.stop()


class TestSocketRoundTrip:
    @requires_udp_replies
    def test_udp_round_trip_and_answers_on(self):
        port = free_port_pair()
        engine, _ = make_engine()
        server = DnsFilterServer(engine, port=port)
        bound = server.start()
        try:
            assert ("127.0.0.1", port) in bound
            assert server.answers_on("127.0.0.1", timeout=2)
            with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as sock:
                sock.settimeout(2)
                sock.connect(("127.0.0.1", port))
                sock.send(build_query("ads.example.com"))
                data, _ = sock.recvfrom(65535)
            assert struct.unpack(">H", data[6:8])[0] == 1  # one answer
            assert data[-4:] == b"\x00\x00\x00\x00"
        finally:
            server.stop()
