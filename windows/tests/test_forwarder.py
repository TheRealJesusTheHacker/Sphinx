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


# --- The forwarding chain's floor (bug hunt 2026-10-23) --------------
#
# FILTER-SPEC's chain, as amended after the Android SEV-1: publics
# first, then the machine's own DNS servers as the floor, and the
# resolver that last answered tried first on the next query. This
# edition shipped with no floor and no affinity: on a network where
# both publics are unreachable (ISP interception, filtered port 53,
# a captive portal), every allowed query went unanswered while the
# machine's own DNS — Sphinx off — answered them all.
#
# Harness note: forward_query takes one port for the whole chain
# (production: 53 everywhere), so the two fakes share a port number
# on different addresses — the "public" on 127.0.0.1, the "machine's
# own resolver" on this box's LAN address, exactly as a router's
# floor address is a LAN address, never loopback (the chain builder
# refuses loopback floor entries by construction).


@pytest.fixture(autouse=True)
def _reset_affinity():
    from sphinx_win.core.forwarder import _reset_last_responder

    _reset_last_responder()
    yield
    _reset_last_responder()


def _with_rcode(query, rcode, answers=0):
    response = bytearray(build_response_for(query, answers=answers))
    response[3] = (response[3] & 0xF0) | rcode
    return bytes(response)


def _rcode_of(packet):
    return packet[3] & 0x0F


def _lan_address():
    """This box's primary LAN address, or None when it has none."""
    try:
        with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as probe:
            probe.connect(("192.0.2.1", 53))
            address = probe.getsockname()[0]
        return address if not address.startswith("127.") else None
    except OSError:
        return None


class CountingUpstream:
    """A UDP responder bound to (host, port) that serves until
    closed and records what it received. ``script(query)`` returns
    the packets to send back (or none, to be silent). Replies go
    out on a connected socket, like the existing harness (this
    repo's sandboxes can block unconnected sendto)."""

    def __init__(self, host, port, script):
        self.sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        self.sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        self.sock.bind((host, port))
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
            replies = self.script(data) or []
            if not replies:
                continue
            try:
                # Reply on the listening socket itself, connected
                # to the asker (the existing harness's discipline:
                # unconnected sendto to ephemeral ports is blocked
                # in some sandboxes, and only this socket's replies
                # are delivered there).
                self.sock.connect(addr)
                for reply in replies:
                    self.sock.send(reply)
                # Rebind for the next query: it arrives from a new
                # ephemeral port, and a connected socket filters by
                # peer — and disconnect() is neither portable nor
                # honored by every sandbox's socket layer. A fresh
                # socket on the same address+port is. The forwarder
                # sends nothing during the gap (it is waiting for
                # this reply), so no query can be lost to it.
                host, port = self.sock.getsockname()[:2]
                family = self.sock.family
                self.sock.close()
                self.sock = socket.socket(family, socket.SOCK_DGRAM)
                self.sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
                self.sock.bind((host, port))
            except OSError:
                return

    def close(self):
        self.sock.close()


def _require_working_lan_floor():
    """Probe the LAN-floor path once per test: some sandboxes drop
    non-loopback UDP outright, and there the floor tests cannot
    run — CI (ordinary networking) is their proof, the same call
    the Debian suite's UDP probe makes. The probe uses throwaway
    fakes so the real pair's counters stay clean."""
    address = _lan_address()
    if address is None:
        pytest.skip("no non-loopback LAN address for the fake floor")
    from sphinx_win.core.forwarder import _reset_last_responder

    probe = CountingUpstream(address, 0, lambda q: [build_response_for(q)])
    try:
        answer = forward_query(
            build_query("example.com"),
            resolvers=(address,),
            port=probe.port,
            timeout=1.0,
        )
    finally:
        probe.close()
        # The probe answered, so it set the forwarder's responder
        # affinity to the floor address: left in place, the test's
        # own first query would try the floor FIRST and the public
        # would never be asked — the exact order the chain tests
        # exist to prove. Reset it; the probe was scaffolding.
        _reset_last_responder()
    if answer is None:
        pytest.skip(
            "non-loopback UDP is blocked in this environment; runs in CI"
        )
    return address


def _public_floor_pair(public_script, floor_script):
    """(port, public, floor_addr, floor): the public fake on
    127.0.0.1 and the floor fake on the LAN address, one port."""
    floor_addr = _require_working_lan_floor()
    public = CountingUpstream("127.0.0.1", 0, public_script)
    try:
        floor = CountingUpstream(floor_addr, public.port, floor_script)
    except OSError:
        public.close()
        pytest.skip("could not bind the fake floor on the LAN address")
    return public.port, public, floor_addr, floor


class TestUpstreamChain:
    def test_chain_is_publics_then_floor_deduped_and_capped(self):
        from sphinx_win.core.forwarder import upstream_chain

        chain = upstream_chain(
            ("1.1.1.1", "9.9.9.9"),
            ("192.168.1.1", "1.1.1.1", "10.0.0.1", "8.8.8.8"),
        )
        # The duplicate public is not repeated; the floor is
        # capped at two (timeout stacking stays bounded).
        assert chain == ["1.1.1.1", "9.9.9.9", "192.168.1.1", "10.0.0.1"]

    def test_chain_refuses_loopback_and_non_address_floor_entries(self):
        from sphinx_win.core.forwarder import upstream_chain

        chain = upstream_chain(
            ("1.1.1.1",),
            ("127.0.0.1", "127.0.0.53", "::1", "not-an-address", "192.168.1.1"),
        )
        assert chain == ["1.1.1.1", "192.168.1.1"]

    def test_chain_keeps_ipv6_floor_literals(self):
        from sphinx_win.core.forwarder import upstream_chain

        chain = upstream_chain(("1.1.1.1",), ("2001:4860:4860::8888",))
        assert chain == ["1.1.1.1", "2001:4860:4860::8888"]


class TestFloor:
    def test_floor_answers_when_the_public_is_silent(self):
        port, public, floor_addr, floor = _public_floor_pair(
            lambda q: [], lambda q: [build_response_for(q)]
        )
        try:
            answer = forward_query(
                build_query("example.com"),
                resolvers=("127.0.0.1",),
                system_resolvers=(floor_addr,),
                port=port,
                timeout=0.4,
            )
            assert answer is not None
            assert _rcode_of(answer) == 0
            assert len(public.received) == 1  # public tried first
            assert len(floor.received) == 1  # then the floor
        finally:
            public.close()
            floor.close()

    def test_dead_publics_then_floor_the_android_sev1_shape(self):
        # Both publics unroutable (the owner's-network shape): the
        # floor is the only thing that answers, and it does.
        floor_addr = _require_working_lan_floor()
        floor = CountingUpstream(
            floor_addr, 0, lambda q: [build_response_for(q)]
        )
        try:
            answer = forward_query(
                build_query("example.com"),
                resolvers=("192.0.2.1", "192.0.2.2"),
                system_resolvers=(floor_addr,),
                port=floor.port,
                timeout=0.4,
            )
            assert answer is not None
            assert len(floor.received) == 1
        finally:
            floor.close()

    def test_no_floor_means_the_old_silence(self):
        # The pre-fix behavior, pinned so the floor's arrival is
        # what changes it: a dead public and no floor = unanswered.
        answer = forward_query(
            build_query("example.com"),
            resolvers=("192.0.2.1",),
            port=free_udp_port(),
            timeout=0.3,
        )
        assert answer is None

    def test_servfail_from_the_public_falls_through_to_the_floor(self):
        port, public, floor_addr, floor = _public_floor_pair(
            lambda q: [_with_rcode(q, 2)], lambda q: [build_response_for(q)]
        )
        try:
            answer = forward_query(
                build_query("example.com"),
                resolvers=("127.0.0.1",),
                system_resolvers=(floor_addr,),
                port=port,
                timeout=1.0,
            )
            assert answer is not None
            assert _rcode_of(answer) == 0  # the floor's answer, not SERVFAIL
        finally:
            public.close()
            floor.close()

    def test_when_every_resolver_fails_the_failure_is_the_answer(self):
        port, public, floor_addr, floor = _public_floor_pair(
            lambda q: [_with_rcode(q, 2)], lambda q: [_with_rcode(q, 2)]
        )
        try:
            answer = forward_query(
                build_query("example.com"),
                resolvers=("127.0.0.1",),
                system_resolvers=(floor_addr,),
                port=port,
                timeout=1.0,
            )
            assert answer is not None
            assert _rcode_of(answer) == 2  # SERVFAIL handed back, not silence
        finally:
            public.close()
            floor.close()

    def test_public_nxdomain_does_not_bury_a_local_name(self):
        port, public, floor_addr, floor = _public_floor_pair(
            lambda q: [_with_rcode(q, 3)], lambda q: [build_response_for(q)]
        )
        try:
            answer = forward_query(
                build_query("printer.lan"),
                resolvers=("127.0.0.1",),
                system_resolvers=(floor_addr,),
                port=port,
                timeout=1.0,
            )
            assert answer is not None
            assert _rcode_of(answer) == 0  # the network's own answer wins
            assert len(floor.received) == 1
        finally:
            public.close()
            floor.close()

    def test_public_nxdomain_for_a_public_name_stands_at_once(self):
        port, public, floor_addr, floor = _public_floor_pair(
            lambda q: [_with_rcode(q, 3)], lambda q: [build_response_for(q)]
        )
        try:
            answer = forward_query(
                build_query("no-such-name.example.com"),
                resolvers=("127.0.0.1",),
                system_resolvers=(floor_addr,),
                port=port,
                timeout=1.0,
            )
            assert answer is not None
            assert _rcode_of(answer) == 3  # NXDOMAIN returned as-is
            assert floor.received == []  # the floor was never asked
        finally:
            public.close()
            floor.close()

    def test_affinity_tries_the_last_responder_first(self):
        import time as _time

        port, public, floor_addr, floor = _public_floor_pair(
            lambda q: [], lambda q: [build_response_for(q)]
        )
        try:
            query = build_query("example.com")
            kwargs = dict(
                resolvers=("127.0.0.1",),
                system_resolvers=(floor_addr,),
                port=port,
                timeout=0.5,
            )
            assert forward_query(query, **kwargs) is not None
            assert len(public.received) == 1  # first query paid the wait
            # Harness settle, not product behavior: the fake floor
            # rebinds its socket between replies (see CountingUpstream),
            # and a query landing in that gap would be refused by the
            # kernel before the chain is even consulted. A real
            # resolver has no such gap.
            _time.sleep(0.1)
            started = _time.monotonic()
            assert forward_query(query, **kwargs) is not None
            elapsed = _time.monotonic() - started
            # Second query went to the floor first: the dead public
            # was not re-tried ahead of it, and no timeout was paid.
            assert len(public.received) == 1
            assert len(floor.received) == 2
            assert elapsed < 0.5
        finally:
            public.close()
            floor.close()


def test_ipv6_public_upstream_answers():
    try:
        probe = socket.socket(socket.AF_INET6, socket.SOCK_DGRAM)
        probe.bind(("::1", 0))
        probe.close()
    except OSError:
        pytest.skip("IPv6 loopback unavailable in this environment")
    port = None
    upstream = CountingUpstream.__new__(CountingUpstream)
    upstream.sock = socket.socket(socket.AF_INET6, socket.SOCK_DGRAM)
    upstream.sock.bind(("::1", 0))
    upstream.port = upstream.sock.getsockname()[1]
    upstream.script = lambda q: [build_response_for(q)]
    upstream.received = []
    def _serve6():
        try:
            data, addr = upstream.sock.recvfrom(65535)
            upstream.received.append(data)
            upstream.sock.connect(addr)
            for reply in upstream.script(data) or []:
                upstream.sock.send(reply)
        except OSError:
            pass

    upstream._thread = threading.Thread(target=_serve6, daemon=True)
    upstream._thread.start()
    try:
        answer = forward_query(
            build_query("example.com"),
            resolvers=("::1",),
            port=upstream.port,
            timeout=1.0,
        )
        assert answer is not None
    finally:
        upstream.close()
