"""The DNS filter itself: a loopback DNS server that questions every
query it receives (FILTER-SPEC).

- Blocked names get the spec's sinkhole answer, built locally.
- Allowed queries are counted at the decision (the audited Android
  semantics — an upstream failure must not make a let-through query
  vanish from both counters) and forwarded unchanged; if no upstream
  answers, the query goes unanswered and the asker retries.
- The query log is memory-only, capped, and never persisted or
  transmitted (FILTER-SPEC, "Counting and the query log").

The engine is transport-free and unit-testable; thin socketserver
wrappers below serve it over UDP and TCP on loopback.
"""
from __future__ import annotations

import socket
import socketserver
import threading
import time
from typing import Callable, List, Optional, Tuple

from .blocklist import FilterLists
from .dnswire import build_sinkhole_response, parse_query
from .forwarder import Forwarder, forward_query
from .querylog import QueryLog

#: Where the system DNS gets pointed. The filter binds both loopback
#: families: Windows consults IPv6 DNS servers in parallel with IPv4
#: ones, so an IPv4-only listener would leave a bypass lane open.
LOOPBACK_V4 = "127.0.0.1"
LOOPBACK_V6 = "::1"
DNS_PORT = 53


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

    def handle_query(self, data: bytes) -> Optional[bytes]:
        """Answer one raw DNS query, or None to leave it unanswered.
        Nothing in here may raise: one malformed packet gets dropped,
        never takes the filter down with it."""
        try:
            query = parse_query(data)
            if query is None or query.is_response:
                return None
            lists = self._lists_provider()
            blocked = lists.is_blocked(query.question_name)
            if self.log_enabled:
                self.query_log.record(
                    query.question_name, blocked, self._clock_ms()
                )
            if blocked:
                with self._lock:
                    self.blocked_count += 1
                return build_sinkhole_response(query)
            with self._lock:
                self.allowed_count += 1
            return self._forwarder(data)
        except Exception:
            # Dropped. Hostile input ends here, quietly.
            return None


class _UdpHandler(socketserver.BaseRequestHandler):
    def handle(self) -> None:
        data, sock = self.request
        response = self.server.engine.handle_query(data)  # type: ignore[attr-defined]
        if response is not None:
            try:
                sock.sendto(response, self.client_address)
            except OSError:
                pass


class _TcpHandler(socketserver.BaseRequestHandler):
    def handle(self) -> None:
        try:
            header = self._read_exactly(2)
            if header is None:
                return
            length = (header[0] << 8) | header[1]
            query = self._read_exactly(length)
            if query is None:
                return
            response = self.server.engine.handle_query(query)  # type: ignore[attr-defined]
            if response is not None:
                self.request.sendall(len(response).to_bytes(2, "big") + response)
        except OSError:
            pass

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

    def answers_on(self, address: str, timeout: float = 2.0) -> bool:
        """Prove the filter answers on ``address``: send a real query
        for a name no list blocks and require a parseable response.
        Used before the system DNS is pointed here — the machine is
        never aimed at a resolver that doesn't answer."""
        from .dnswire import parse_query as _parse  # local to avoid cycles in docs

        query = (
            (0x5EED).to_bytes(2, "big")  # ID
            + (0x0100).to_bytes(2, "big")  # RD
            + (1).to_bytes(2, "big")  # QDCOUNT
            + (0).to_bytes(2, "big") * 3
            + bytes([7]) + b"example" + bytes([3]) + b"com" + bytes([0])
            + (1).to_bytes(2, "big")  # A
            + (1).to_bytes(2, "big")  # IN
        )
        family = socket.AF_INET6 if ":" in address else socket.AF_INET
        try:
            with socket.socket(family, socket.SOCK_DGRAM) as sock:
                sock.settimeout(timeout)
                sock.connect((address, self.port))
                sock.send(query)
                data, _ = sock.recvfrom(65535)
        except OSError:
            return False
        response = _parse(data)
        return response is not None and response.is_response and response.id == 0x5EED
