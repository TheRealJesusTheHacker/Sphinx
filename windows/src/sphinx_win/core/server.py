"""The DNS filter itself: a loopback DNS server that questions every
query it receives (FILTER-SPEC).

- Blocked names get the spec's sinkhole answer, built locally.
- Allowed queries are counted at the decision (the audited Android
  semantics — an upstream failure must not make a let-through query
  vanish from both counters) and forwarded unchanged; if no upstream
  answers, the query goes unanswered and the asker retries.
- The query log is memory-only, capped, and never persisted or
  transmitted (FILTER-SPEC, "Counting and the query log").
- Concurrency is bounded: at most MAX_IN_FLIGHT_QUERIES queries are
  being worked on at once across all listeners. Queries past the
  cap are refused — a UDP query goes unanswered (the asker retries,
  as on an upstream timeout) and a TCP connection is closed — so a
  flooding app cannot grow the process without limit. The counters
  count queries actually processed, so under an extreme flood they
  understate the total stopped; bounded memory wins over exact
  bookkeeping in a flood. (The Android edition's Phase 3 audit made
  the same call for the same reason.)
- The server's own liveness proof (answers_on) is not user traffic:
  its exchange is answered by the engine but never counted and
  never logged.

The engine is transport-free and unit-testable; thin socketserver
wrappers below serve it over UDP and TCP on loopback.
"""
from __future__ import annotations

import os
import socket
import socketserver
import threading
import time
from typing import Callable, List, Optional, Tuple

from .blocklist import FilterLists
from .dnswire import build_sinkhole_response, parse_query
from .forwarder import (
    UPSTREAM_RESOLVERS,
    UPSTREAM_TIMEOUT_S,
    Forwarder,
    forward_query,
)
from .querylog import QueryLog

#: Where the system DNS gets pointed. The filter binds both loopback
#: families: Windows consults IPv6 DNS servers in parallel with IPv4
#: ones, so an IPv4-only listener would leave a bypass lane open.
LOOPBACK_V4 = "127.0.0.1"
LOOPBACK_V6 = "::1"
DNS_PORT = 53

#: How many queries may be in flight across all listeners at once.
#: Everything past this is refused (see the module notes).
MAX_IN_FLIGHT_QUERIES = 64

#: A TCP client that stalls mid-query loses its slot after this long.
TCP_READ_TIMEOUT_S = 10.0

#: How long the liveness proof (answers_on) waits by default. The
#: proof queries an allowed name, so its answer comes back through
#: the forwarder — whose worst case is one full timeout per
#: upstream resolver. The proof's budget must exceed that worst
#: case, or a healthy filter can fail its own proof on a machine
#: whose first resolver is unreachable and whose second is slow
#: (Sweep #3, W-6). One second of headroom over the worst case;
#: the fail-safe property is unchanged — DNS never moves unless
#: the proof actually passes.
PROOF_TIMEOUT_S = len(UPSTREAM_RESOLVERS) * UPSTREAM_TIMEOUT_S + 1.0


class FilterEngine:
    """The per-query decision, independent of any socket.

    ``lists_provider`` is called for every query, so a list reload is
    just the provider returning a new FilterLists — a restart or an
    update applies *all* state, never a half-swapped set (the Android
    Phase 4 audit lesson).
    """

    def __init__(
        self,
        lists_provider: Callable[[], FilterLists],
        forwarder: Forwarder = forward_query,
        query_log: Optional[QueryLog] = None,
        log_enabled: bool = True,
        clock_ms: Callable[[], int] = lambda: int(time.time() * 1000),
    ):
        self._lists_provider = lists_provider
        self._forwarder = forwarder
        self.query_log = query_log if query_log is not None else QueryLog()
        self.log_enabled = log_enabled
        self._clock_ms = clock_ms
        self._lock = threading.Lock()
        self.blocked_count = 0
        self.allowed_count = 0

    def set_forwarder(self, forwarder: Forwarder) -> None:
        """Swap the upstream forwarder (VPN + Blocker mode points
        allowed queries at the profile's DNS servers through the
        tunnel, TUNNEL-SPEC's mode model; disconnecting restores
        the default). The DNS decision itself never changes with
        the forwarder: blocked names are sinkholed locally and
        immediately either way, and an unlisted name is forwarded
        through the forwarder's full fallback discipline — the
        forwarder is replaced whole, never wrapped in a way that
        could swallow a query the fallback would have answered."""
        self._forwarder = forwarder

    def reload(self) -> None:
        """Force the next query to re-read the provider's lists.

        With the provider reading from the store this is a no-op
        cache-wise; it exists so the app has one explicit "apply all
        state" call after edits and updates.
        """
        # The provider is consulted per query by design; nothing is
        # cached here to invalidate. Kept as the app's single entry
        # point so future caching has exactly one flush to update.
        return None

    def handle_query(self, data: bytes, record: bool = True) -> Optional[bytes]:
        """Answer one raw DNS query, or None to leave it unanswered.
        Nothing in here may raise: one malformed packet gets dropped,
        never takes the filter down with it.

        ``record=False`` is for the server's own liveness proof: the
        decision and the answer are identical, but the exchange is
        not the user's traffic, so it is neither counted nor logged.
        """
        try:
            query = parse_query(data)
            if query is None or query.is_response:
                return None
            lists = self._lists_provider()
            blocked = lists.is_blocked(query.question_name)
            if record and self.log_enabled:
                self.query_log.record(
                    query.question_name, blocked, self._clock_ms()
                )
            if blocked:
                if record:
                    with self._lock:
                        self.blocked_count += 1
                return build_sinkhole_response(query)
            if record:
                with self._lock:
                    self.allowed_count += 1
            return self._forwarder(data)
        except Exception:
            # Dropped. Hostile input ends here, quietly.
            return None


class _UdpHandler(socketserver.BaseRequestHandler):
    def handle(self) -> None:
        data, sock = self.request
        slots = self.server.work_slots  # type: ignore[attr-defined]
        if not slots.acquire(blocking=False):
            return  # at capacity: unanswered; the asker retries
        try:
            response = self.server.dispatch(data)  # type: ignore[attr-defined]
            if response is not None:
                try:
                    sock.sendto(response, self.client_address)
                except OSError:
                    pass
        finally:
            slots.release()


class _TcpHandler(socketserver.BaseRequestHandler):
    def handle(self) -> None:
        slots = self.server.work_slots  # type: ignore[attr-defined]
        if not slots.acquire(blocking=False):
            return  # at capacity: refuse (returning closes the connection)
        try:
            self.request.settimeout(TCP_READ_TIMEOUT_S)
            header = self._read_exactly(2)
            if header is None:
                return
            length = (header[0] << 8) | header[1]
            query = self._read_exactly(length)
            if query is None:
                return
            response = self.server.dispatch(query)  # type: ignore[attr-defined]
            if response is not None:
                self.request.sendall(len(response).to_bytes(2, "big") + response)
        except OSError:
            pass
        finally:
            slots.release()

    def _read_exactly(self, count: int) -> Optional[bytes]:
        chunks = bytearray()
        while len(chunks) < count:
            chunk = self.request.recv(count - len(chunks))
            if not chunk:
                return None
            chunks.extend(chunk)
        return bytes(chunks)


class _ThreadingUDPServer(socketserver.ThreadingUDPServer):
    daemon_threads = True
    allow_reuse_address = True


class _ThreadingTCPServer(socketserver.ThreadingTCPServer):
    daemon_threads = True
    allow_reuse_address = True


class _ThreadingUDPServerV6(_ThreadingUDPServer):
    address_family = socket.AF_INET6


class _ThreadingTCPServerV6(_ThreadingTCPServer):
    address_family = socket.AF_INET6


class DnsFilterServer:
    """Serves a FilterEngine on loopback, UDP + TCP, both families.

    IPv6 loopback is best-effort: a machine without IPv6 still gets
    the full IPv4 filter, and ``bound_addresses`` says honestly what
    was actually bound (the DNS manager is pointed only at loopbacks
    that answer).
    """

    def __init__(self, engine: FilterEngine, port: int = DNS_PORT):
        self.engine = engine
        self.port = port
        self._servers: List[socketserver.BaseServer] = []
        self._threads: List[threading.Thread] = []
        self.bound_addresses: List[Tuple[str, int]] = []
        # One concurrency budget shared by every listener (see the
        # module notes), and the one-shot token identifying the
        # liveness proof's own query while it is in flight.
        self._work_slots = threading.BoundedSemaphore(MAX_IN_FLIGHT_QUERIES)
        self._proof_lock = threading.Lock()
        self._proof: Optional[Tuple[int, str]] = None

    def _dispatch(self, data: bytes) -> Optional[bytes]:
        """The handlers' road into the engine. The liveness proof's
        exchange is answered like any other query but is not the
        user's traffic, so it is neither counted nor logged."""
        return self.engine.handle_query(data, record=not self._consume_proof(data))

    def _consume_proof(self, data: bytes) -> bool:
        with self._proof_lock:
            proof = self._proof
        if proof is None:
            return False
        parsed = parse_query(data)
        if parsed is None or parsed.is_response:
            return False
        if (parsed.id, parsed.question_name) != proof:
            return False
        with self._proof_lock:
            if self._proof == proof:
                self._proof = None
                return True
        return False

    def start(self) -> List[Tuple[str, int]]:
        plan = [
            (_ThreadingUDPServer, (LOOPBACK_V4, self.port), True),
            (_ThreadingTCPServer, (LOOPBACK_V4, self.port), True),
            (_ThreadingUDPServerV6, (LOOPBACK_V6, self.port), False),
            (_ThreadingTCPServerV6, (LOOPBACK_V6, self.port), False),
        ]
        bound = set()
        for cls, address, required in plan:
            try:
                server = cls(address, _UdpHandler if "UDP" in cls.__name__ else _TcpHandler)
            except OSError:
                if required:
                    self.stop()
                    raise
                continue
            server.engine = self.engine  # type: ignore[attr-defined]
            server.work_slots = self._work_slots  # type: ignore[attr-defined]
            server.dispatch = self._dispatch  # type: ignore[attr-defined]
            self._servers.append(server)
            bound.add(address)
        self.bound_addresses = sorted(bound)
        for server in self._servers:
            thread = threading.Thread(
                target=server.serve_forever,
                kwargs={"poll_interval": 0.05},
                daemon=True,
            )
            thread.start()
            self._threads.append(thread)
        return list(self.bound_addresses)

    def stop(self) -> None:
        for server in self._servers:
            try:
                server.shutdown()
            except Exception:
                pass
            try:
                server.server_close()
            except Exception:
                pass
        self._servers.clear()
        self._threads.clear()
        self.bound_addresses = []

    def answers_on(self, address: str, timeout: float = PROOF_TIMEOUT_S) -> bool:
        """Prove the filter answers on ``address``: send a real query
        for a name no list blocks and require a parseable response.
        Used before the system DNS is pointed here — the machine is
        never aimed at a resolver that doesn't answer. The exchange
        is registered as the liveness proof first, so the engine
        answers it without counting or logging it (see _dispatch).
        The default timeout is PROOF_TIMEOUT_S — above the
        forwarder's worst case, because this proof's answer comes
        back through that forwarder (see the constant)."""
        from .dnswire import parse_query as _parse  # local to avoid cycles in docs

        proof_id = int.from_bytes(os.urandom(2), "big")
        proof = (proof_id, "example.com")
        query = (
            proof_id.to_bytes(2, "big")  # ID
            + (0x0100).to_bytes(2, "big")  # RD
            + (1).to_bytes(2, "big")  # QDCOUNT
            + (0).to_bytes(2, "big") * 3
            + bytes([7]) + b"example" + bytes([3]) + b"com" + bytes([0])
            + (1).to_bytes(2, "big")  # A
            + (1).to_bytes(2, "big")  # IN
        )
        family = socket.AF_INET6 if ":" in address else socket.AF_INET
        with self._proof_lock:
            self._proof = proof
        try:
            with socket.socket(family, socket.SOCK_DGRAM) as sock:
                sock.settimeout(timeout)
                sock.connect((address, self.port))
                sock.send(query)
                data, _ = sock.recvfrom(65535)
        except OSError:
            return False
        finally:
            with self._proof_lock:
                if self._proof == proof:
                    self._proof = None
        response = _parse(data)
        return (
            response is not None
            and response.is_response
            and response.id == proof_id
        )
