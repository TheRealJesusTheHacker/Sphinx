"""Forwarding of allowed queries to an upstream resolver —
FILTER-SPEC, "Forwarding behavior (allowed queries)", ported from
the Android edition's forwarding path, with its audited validation
discipline:

- The query is forwarded unchanged over UDP/53 — default 1.1.1.1,
  fallback 9.9.9.9 — timeout 3 seconds per upstream attempt; the
  fallback is tried once before giving up. If both fail, the query
  goes unanswered (the asking app retries on its own schedule).
- The socket is *connected* to the resolver, so the OS only delivers
  datagrams that actually come from it, and a response counts as the
  answer only if its DNS ID matches the query's ID with the response
  (QR) bit set. Anything else arriving on the socket is ignored — a
  stray or spoofed datagram is never delivered to the asker.
- The 3-second budget covers the whole wait, not each datagram, so a
  stream of mismatched packets cannot stretch it forever.

Windows note: Android protects the forwarding socket from its own
VPN; here there is no tunnel to loop into — the filter is a local
DNS server and its upstream sockets go straight out the machine's
network, never to 127.0.0.1 (the upstreams are public resolvers),
so no equivalent guard is needed.
"""
from __future__ import annotations

import ipaddress
import socket
import time
from typing import Callable, Optional, Sequence

DNS_PORT = 53
UPSTREAM_RESOLVERS = ("1.1.1.1", "9.9.9.9")
UPSTREAM_TIMEOUT_S = 3.0
_MAX_PACKET = 65535


def _is_answer(data: bytes, query_id: int) -> bool:
    return (
        len(data) >= 4
        and ((data[0] << 8) | data[1]) == query_id
        and bool(data[2] & 0x80)  # QR bit
    )


def _is_truncated(data: bytes) -> bool:
    return len(data) >= 3 and bool(data[2] & 0x02)  # TC bit


def _family(resolver: str) -> socket.AddressFamily:
    """The socket family a resolver address needs. VPN profiles
    may name IPv6 DNS servers (the profile parser accepts any IP
    literal, and the controller's tunnel-DNS path already splits
    servers by family); an AF_INET socket cannot reach one — its
    connect fails as a resolver failure, so a profile whose DNS
    is IPv6-only would leave every allowed query unanswered in
    VPN + Blocker mode. The Debian edition's forwarder already
    chooses the family per resolver; this is the same rule."""
    try:
        return socket.AF_INET6 if ipaddress.ip_address(resolver).version == 6 else socket.AF_INET
    except ValueError:
        return socket.AF_INET


def _tcp_exchange(
    query: bytes, resolver: str, deadline: float, port: int = DNS_PORT
) -> Optional[bytes]:
    """Redo a truncated query over TCP (RFC 7766): length-prefixed
    query, length-prefixed answer, same overall deadline."""
    remaining = deadline - time.monotonic()
    if remaining <= 0:
        return None
    try:
        with socket.create_connection(
            (resolver, port), timeout=remaining
        ) as conn:
            conn.sendall(len(query).to_bytes(2, "big") + query)
            header = _recv_exactly(conn, 2, deadline)
            if header is None:
                return None
            length = (header[0] << 8) | header[1]
            return _recv_exactly(conn, length, deadline)
    except OSError:
        return None


def _recv_exactly(conn: socket.socket, count: int, deadline: float) -> Optional[bytes]:
    chunks = bytearray()
    while len(chunks) < count:
        remaining = deadline - time.monotonic()
        if remaining <= 0:
            return None
        conn.settimeout(remaining)
        try:
            chunk = conn.recv(count - len(chunks))
        except OSError:
            return None
        if not chunk:
            return None
        chunks.extend(chunk)
    return bytes(chunks)


def forward_query(
    query: bytes,
    resolvers: Sequence[str] = UPSTREAM_RESOLVERS,
    timeout: float = UPSTREAM_TIMEOUT_S,
    port: int = DNS_PORT,
) -> Optional[bytes]:
    """Send a DNS query to the upstream resolvers; None if all fail.

    ``port`` is a parameter so tests can point the forwarder at a
    local fake upstream; production always uses 53.
    """
    if len(query) < 2:
        return None
    query_id = (query[0] << 8) | query[1]
    for resolver in resolvers:
        sock = socket.socket(_family(resolver), socket.SOCK_DGRAM)
        try:
            # Connected, not just addressed: the kernel then only
            # delivers datagrams that actually come from this
            # resolver, so a stray or spoofed packet from anything
            # else on the network can't be mistaken for the answer.
            sock.connect((resolver, port))
            sock.send(query)
            deadline = time.monotonic() + timeout
            while True:
                remaining = deadline - time.monotonic()
                if remaining <= 0:
                    break
                sock.settimeout(remaining)
                try:
                    data, _ = sock.recvfrom(_MAX_PACKET)
                except OSError:
                    break  # timeout or socket error: next resolver
                if _is_answer(data, query_id):
                    if _is_truncated(data):
                        # Truncated answers are completed over TCP,
                        # like every stub resolver does; if TCP
                        # fails, hand back the truncated answer and
                        # let the asker retry as it sees fit.
                        full = _tcp_exchange(query, resolver, deadline, port)
                        return full if full is not None and _is_answer(full, query_id) else data
                    return data
                # Not our answer: ignore it and keep waiting — but
                # the deadline above bounds the whole wait.
        except OSError:
            pass  # connect/send failure: try the next resolver
        finally:
            sock.close()
    return None


#: The forwarder signature the filter engine depends on.
Forwarder = Callable[[bytes], Optional[bytes]]
