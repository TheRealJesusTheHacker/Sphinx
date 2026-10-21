"""The forwarding discipline, against fake upstreams on loopback:
connected-socket validation (only the resolver's own datagrams with
the query's ID and the QR bit set count), the single overall
deadline, the one fallback attempt, and TCP completion of truncated
answers. (FILTER-SPEC, "Forwarding behavior".)"""
import socket
import threading
import time

import pytest

from conftest import requires_udp
from sphinx_deb.core.dnswire import build_query, parse_query
from sphinx_deb.core.forwarder import forward_query

pytestmark = requires_udp


def _response_for(query: bytes, *, truncated: bool = False, qr: bool = True,
                  query_id=None) -> bytes:
    parsed = parse_query(query)
    out = bytearray(query)
    qid = parsed.id if query_id is None else query_id
    out[0:2] = qid.to_bytes(2, "big")
    flags = 0x8000 | 0x0080 | (0x0200 if truncated else 0)
    if not qr:
        flags &= ~0x8000
    out[2:4] = flags.to_bytes(2, "big")
    return bytes(out)


class FakeUpstream:
    """A UDP responder on a loopback high port, scripted per test."""

    def __init__(self, script):
        self.sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        self.sock.bind(("127.0.0.1", 0))
        self.port = self.sock.getsockname()[1]
        self.script = script
        self.received = []
        self._thread = threading.Thread(target=self._serve, daemon=True)
        self._thread.start()

    def _serve(self):
        while True:
            try:
                data, addr = self.sock.recvfrom(65535)
            except OSError:
                return
            self.received.append(data)
            for reply in self.script(data) or []:
                self.sock.sendto(reply, addr)

    def close(self):
        self.sock.close()


def _query():
    return build_query("example.com", query_id=0x4242)


def test_happy_path_returns_the_upstreams_answer_unchanged():
    upstream = FakeUpstream(lambda q: [_response_for(q)])
    try:
        answer = forward_query(_query(), resolvers=("127.0.0.1",),
                               timeout=1.0, port=upstream.port)
        assert answer == _response_for(_query())
    finally:
        upstream.close()


def test_wrong_id_and_qr_clear_datagrams_are_ignored():
    def script(q):
        return [
            _response_for(q, query_id=0x9999),  # spoofed ID
            _response_for(q, qr=False),         # not a response
            _response_for(q),                   # the real answer
        ]

    upstream = FakeUpstream(script)
    try:
        answer = forward_query(_query(), resolvers=("127.0.0.1",),
                               timeout=2.0, port=upstream.port)
        assert answer == _response_for(_query())
    finally:
        upstream.close()


def test_fallback_is_tried_once_when_the_first_is_silent():
    silent = FakeUpstream(lambda q: [])
    answering = FakeUpstream(lambda q: [_response_for(q)])
    try:
        answer = forward_query(
            _query(), resolvers=("127.0.0.1", "127.0.0.1"), timeout=0.4,
            port=silent.port,
        )
        assert answer is None  # same port twice: still the silent one
        # Point the fallback at the answering upstream via a second call
        # shape: resolver list is tried in order, each on the given port
        # — here both ports differ, so use two forwarders' ports by
        # calling with the answering port and a dead resolver address.
        answer = forward_query(
            _query(), resolvers=("192.0.2.1", "127.0.0.1"), timeout=0.6,
            port=answering.port,
        )
        assert answer == _response_for(_query())
    finally:
        silent.close()
        answering.close()


def test_both_failing_means_unanswered():
    silent = FakeUpstream(lambda q: [])
    try:
        started = time.monotonic()
        answer = forward_query(_query(), resolvers=("127.0.0.1",),
                               timeout=0.3, port=silent.port)
        assert answer is None
        assert time.monotonic() - started < 2.0  # the deadline held
    finally:
        silent.close()


def test_truncated_udp_answer_is_completed_over_tcp():
    query = _query()
    full = _response_for(query)
    truncated = _response_for(query, truncated=True)

    udp = FakeUpstream(lambda q: [truncated])
    tcp = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    tcp.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    tcp.bind(("127.0.0.1", udp.port))
    tcp.listen(1)

    def serve_tcp():
        conn, _ = tcp.accept()
        with conn:
            header = conn.recv(2)
            length = int.from_bytes(header, "big")
            data = b""
            while len(data) < length:
                data += conn.recv(length - len(data))
            conn.sendall(len(full).to_bytes(2, "big") + full)

    thread = threading.Thread(target=serve_tcp, daemon=True)
    thread.start()
    try:
        answer = forward_query(query, resolvers=("127.0.0.1",),
                               timeout=2.0, port=udp.port)
        assert answer == full
    finally:
        udp.close()
        tcp.close()
