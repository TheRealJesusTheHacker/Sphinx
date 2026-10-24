"""The forwarder against fake local upstreams: answer validation,
spoof discipline, the overall deadline, TCP completion of truncated
answers."""
import socket
import struct
import threading

import pytest

from sphinx_win.core.forwarder import forward_query
from dnsutil import build_query, build_response_for


def free_udp_port():
    with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as s:
        s.bind(("127.0.0.1", 0))
        return s.getsockname()[1]


class FakeUdpUpstream(threading.Thread):
    """Answers on UDP with a scripted behavior."""

    def __init__(self, port, behavior):
        super().__init__(daemon=True)
        self.port = port
        self.behavior = behavior
        self.sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        self.sock.bind(("127.0.0.1", port))
        self.sock.settimeout(5)

    def run(self):
        try:
            data, addr = self.sock.recvfrom(65535)
            self.behavior(self.sock, data, addr)
        except OSError:
            pass
        finally:
            self.sock.close()


def respond(sock, data, addr, packets):
    # Reply on a connected socket: this repo's build sandbox blocks
    # unconnected sendto() to ephemeral ports (EPERM), while real
    # upstreams (and CI) accept either. connect()+send() exercises
    # the same forwarder path deterministically everywhere.
    sock.connect(addr)
    for packet in packets:
        sock.send(packet)


def test_answer_returned():
    port = free_udp_port()
    query = build_query("example.com")

    def behavior(sock, data, addr):
        respond(sock, data, addr, [build_response_for(data)])

    FakeUdpUpstream(port, behavior).start()
    answer = forward_query(query, resolvers=("127.0.0.1",), port=port, timeout=2)
    assert answer is not None
    assert answer[0:2] == query[0:2]


def test_wrong_id_datagram_is_ignored_not_delivered():
    port = free_udp_port()
    query = build_query("example.com")

    def behavior(sock, data, addr):
        spoof = bytearray(build_response_for(data))
        spoof[0:2] = b"\xde\xad"  # someone else's ID
        good = build_response_for(data)
        respond(sock, data, addr, [bytes(spoof), good])

    FakeUdpUpstream(port, behavior).start()
    answer = forward_query(query, resolvers=("127.0.0.1",), port=port, timeout=2)
    assert answer is not None
    assert answer[0:2] == query[0:2]


def test_ipv6_upstream_is_reached():
    # Sweep #5: a VPN profile may name IPv6 DNS servers, but the
    # forwarder built its socket as AF_INET unconditionally, so
    # an IPv6 upstream's connect always failed and a profile
    # whose DNS is IPv6-only left every allowed query unanswered
    # in VPN + Blocker mode. (The Debian forwarder already picks
    # the family per resolver.) Skip where IPv6 loopback is
    # unavailable in the environment.
    try:
        probe = socket.socket(socket.AF_INET6, socket.SOCK_DGRAM)
        probe.bind(("::1", 0))
        port = probe.getsockname()[1]
        probe.close()
    except OSError:
        pytest.skip("IPv6 loopback unavailable in this environment")
    query = build_query("example.com")
    server = socket.socket(socket.AF_INET6, socket.SOCK_DGRAM)
    server.bind(("::1", port))
    server.settimeout(5)

    def serve():
        try:
            data, addr = server.recvfrom(65535)
            server.connect(addr)
            server.send(build_response_for(data))
        except OSError:
            pass
        finally:
            server.close()

    threading.Thread(target=serve, daemon=True).start()
    answer = forward_query(query, resolvers=("::1",), port=port, timeout=2)
    assert answer is not None
    assert answer[0:2] == query[0:2]


def test_no_answer_returns_none_after_fallback():
    port = free_udp_port()  # nothing listens there
    query = build_query("example.com")
    answer = forward_query(
        query, resolvers=("127.0.0.1", "127.0.0.1"), port=port, timeout=0.3
    )
    assert answer is None


def test_truncated_answer_completed_over_tcp():
    port = free_udp_port()
    query = build_query("big.example.com")
    full_answer = build_response_for(query)

    def udp_behavior(sock, data, addr):
        truncated = bytearray(build_response_for(data, answers=0))
        truncated[2] |= 0x02  # TC bit
        respond(sock, data, addr, [bytes(truncated)])

    FakeUdpUpstream(port, udp_behavior).start()

    tcp_server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    tcp_server.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    tcp_server.bind(("127.0.0.1", port))
    tcp_server.listen(1)
    tcp_server.settimeout(5)

    def serve_tcp():
        try:
            conn, _ = tcp_server.accept()
            with conn:
                header = conn.recv(2)
                length = struct.unpack(">H", header)[0]
                body = b""
                while len(body) < length:
                    body += conn.recv(length - len(body))
                conn.sendall(struct.pack(">H", len(full_answer)) + full_answer)
        except OSError:
            pass
        finally:
            tcp_server.close()

    threading.Thread(target=serve_tcp, daemon=True).start()
    answer = forward_query(query, resolvers=("127.0.0.1",), port=port, timeout=3)
    assert answer == full_answer
