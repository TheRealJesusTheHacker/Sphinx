"""Forwarding of allowed queries to an upstream resolver —
FILTER-SPEC, "Forwarding behavior (allowed queries)", ported from
the Android edition's forwarding path, with its audited validation
discipline:

- The query is forwarded unchanged over UDP/53 to a chain of
  upstreams tried in order: the public resolvers — default
  1.1.1.1, fallback 9.9.9.9 — and then the machine's own DNS
  servers as the chain's floor (the resolvers the machine was
  using before Sphinx engaged, captured at engage time by the
  DNS guard; see dnsmgmt/guard.py). Timeout 3 seconds per
  upstream attempt. Only when every resolver in the chain has
  failed does the query go unanswered (the asking app retries
  on its own schedule). The chain exists under the spec's
  governing rule: an allowed query must never fail merely
  because the public upstreams are unreachable on the current
  network — a carrier or ISP that intercepts or blocks outside
  resolvers, a filtered port 53, an IPv6-only path, a captive
  portal. The unlisted path degrades toward the network's own
  resolution, never toward silence. (The Android edition's
  2026-10-23 SEV-1 was exactly this failure with no floor; this
  edition's host-stack sockets were never the protection they
  were assumed to be — a socket to 1.1.1.1 dies on those
  networks no matter which stack carries it.)
- The resolver that last answered is tried first on the next
  query, so a network where the head of the chain is dead
  converges on the working resolver instead of paying the dead
  attempts' timeouts for every name.
- An answer that is a resolver failure (SERVFAIL, REFUSED) is
  not the chain's last word while another resolver remains —
  the next resolver is tried, and the failure is handed back
  only when every resolver has failed the same way. An NXDOMAIN
  for a name that looks local (a single label, a .local /
  home-style suffix, home.arpa) gets the same treatment: the
  public resolvers cannot know the network's own names, and
  their NXDOMAIN must not bury a name the machine's own DNS
  would have answered. NXDOMAIN for an ordinary public name is
  returned at once, as before.
- The socket is *connected* to the resolver, so the OS only
  delivers datagrams that actually come from it, and a response
  counts as the answer only if its DNS ID matches the query's
  ID with the response (QR) bit set. Anything else arriving on
  the socket is ignored — a stray or spoofed datagram is never
  delivered to the asker.
- The 3-second budget covers the whole wait, not each
  datagram, so a stream of mismatched packets cannot stretch
  it forever.
- Floor entries are never loopbacks: a "machine's own server"
  that sits on this machine is the filter itself (or the
  resolver it replaced), and forwarding there would loop the
  query back into the filter. Non-address entries are refused
  the same way.

Windows note: Android protects the forwarding socket from its
own VPN; here there is no tunnel to loop into — the filter is a
local DNS server and its upstream sockets go straight out the
machine's network. The loop that *can* happen here is the
floor pointing back at the filter's own loopback; the chain
builder above refuses that by construction.
"""
from __future__ import annotations

import ipaddress
import socket
import threading
import time
from typing import Callable, List, Optional, Sequence

from .dnswire import parse_query

DNS_PORT = 53
UPSTREAM_RESOLVERS = ("1.1.1.1", "9.9.9.9")
UPSTREAM_TIMEOUT_S = 3.0

#: How many of the machine's own resolvers the chain carries as
#: its floor. Two bounds the timeout stacking: the longest chain
#: is the two publics plus these, so a fully dead network costs
#: at most four per-attempt timeouts, and the last-responder
#: affinity means a live network pays that only once. (Android
#: allows four; its askers are apps behind a VPN it controls.
#: A machine's stub resolver gives up sooner, so this chain is
#: kept shorter — the floor's first entry is the machine's
#: primary resolver, which is the one that matters.)
MAX_SYSTEM_RESOLVERS = 2

_MAX_PACKET = 65535

_RCODE_SERVFAIL = 2
_RCODE_NXDOMAIN = 3
_RCODE_REFUSED = 5
#: Rcodes that are a resolver failing, not a name's answer.
_FAILURE_RCODES = frozenset({_RCODE_SERVFAIL, _RCODE_REFUSED})

#: Final labels that mark a name as the local network's own —
#: names the public resolvers cannot know (FILTER-SPEC's rule
#: applied honestly: their NXDOMAIN is not evidence the name
#: does not exist on this network).
_LOCAL_FINAL_LABELS = frozenset(
    {
        "local",
        "lan",
        "home",
        "internal",
        "intranet",
        "corp",
        "localdomain",
        "private",
    }
)


def _is_answer(data: bytes, query_id: int) -> bool:
    return (
        len(data) >= 4
        and ((data[0] << 8) | data[1]) == query_id
        and bool(data[2] & 0x80)  # QR bit
    )


def _is_truncated(data: bytes) -> bool:
    return len(data) >= 3 and bool(data[2] & 0x02)  # TC bit


def _rcode(data: bytes) -> int:
    return data[3] & 0x0F if len(data) >= 4 else 0


def _family(resolver: str) -> socket.AddressFamily:
    try:
        return (
            socket.AF_INET6
            if ipaddress.ip_address(resolver).version == 6
            else socket.AF_INET
        )
    except ValueError:
        return socket.AF_INET


def _is_loopback_literal(address: str) -> bool:
    """True for loopback addresses — and for anything that is not
    an IP literal at all, which may never be forwarded to."""
    try:
        return ipaddress.ip_address(address).is_loopback
    except ValueError:
        return True


def _is_local_name(query: bytes) -> bool:
    """True when the queried name looks like the local network's
    own: a single label, a home.arpa name, or a final label from
    the local set. Unparseable queries are not local."""
    parsed = parse_query(query)
    if parsed is None:
        return False
    name = parsed.question_name
    if not name:
        return False
    if "." not in name:
        return True
    if name == "home.arpa" or name.endswith(".home.arpa"):
        return True
    return name.rsplit(".", 1)[-1] in _LOCAL_FINAL_LABELS


def upstream_chain(
    resolvers: Sequence[str],
    system_resolvers: Sequence[str] = (),
) -> List[str]:
    """The chain for one query: ``resolvers`` first (the public
    head, or the daemon's configured upstreams), then the
    machine's own resolvers as the floor — duplicates removed,
    loopbacks and non-addresses refused, the floor capped at
    MAX_SYSTEM_RESOLVERS."""
    chain: List[str] = []
    seen = set()
    for resolver in resolvers:
        if resolver not in seen:
            seen.add(resolver)
            chain.append(resolver)
    floor = 0
    for resolver in system_resolvers:
        if floor >= MAX_SYSTEM_RESOLVERS:
            break
        if resolver in seen or _is_loopback_literal(resolver):
            continue
        seen.add(resolver)
        chain.append(resolver)
        floor += 1
    return chain


# The resolver that answered most recently, tried first on the
# next query (see the module notes). Process-wide, like the
# Android edition's: benign under races — a stale read only
# costs the chain's ordinary order for one query.
_affinity_lock = threading.Lock()
_last_responder: Optional[str] = None


def _reset_last_responder() -> None:
    """Test hook: affinity is process-wide, so tests reset it."""
    global _last_responder
    with _affinity_lock:
        _last_responder = None


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


def _exchange(
    query: bytes, query_id: int, resolver: str, timeout: float, port: int
) -> Optional[bytes]:
    """One upstream attempt: the resolver's answer (any rcode), or
    None when it produced no acceptable answer in the budget."""
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
                return None
            sock.settimeout(remaining)
            try:
                data, _ = sock.recvfrom(_MAX_PACKET)
            except OSError:
                return None  # timeout or socket error
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
        return None  # connect/send failure
    finally:
        sock.close()


def forward_query(
    query: bytes,
    resolvers: Sequence[str] = UPSTREAM_RESOLVERS,
    timeout: float = UPSTREAM_TIMEOUT_S,
    port: int = DNS_PORT,
    system_resolvers: Sequence[str] = (),
) -> Optional[bytes]:
    """Send a DNS query along the upstream chain; None if all fail.

    ``resolvers`` is the chain's head (production: the public
    pair); ``system_resolvers`` is the machine's own DNS, the
    floor the chain degrades toward (production: captured at
    engage time — see the module notes). ``port`` is a parameter
    so tests can point the forwarder at local fake upstreams;
    production always uses 53.
    """
    global _last_responder
    if len(query) < 2:
        return None
    query_id = (query[0] << 8) | query[1]
    chain = upstream_chain(resolvers, system_resolvers)
    if not chain:
        return None
    with _affinity_lock:
        preferred = _last_responder
    if preferred is not None and preferred in chain:
        ordered = [preferred] + [r for r in chain if r != preferred]
    else:
        ordered = list(chain)
    local_name = _is_local_name(query)
    deferred: Optional[bytes] = None
    deferred_from: Optional[str] = None
    for index, resolver in enumerate(ordered):
        answer = _exchange(query, query_id, resolver, timeout, port)
        if answer is None:
            continue
        rcode = _rcode(answer)
        is_last = index == len(ordered) - 1
        if not is_last and (
            rcode in _FAILURE_RCODES
            or (rcode == _RCODE_NXDOMAIN and local_name)
        ):
            # Not the chain's last word (see the module notes):
            # remember the deepest such answer and try on.
            deferred = answer
            deferred_from = resolver
            continue
        with _affinity_lock:
            _last_responder = resolver
        return answer
    if deferred is not None:
        with _affinity_lock:
            _last_responder = deferred_from
        return deferred
    return None


#: The forwarder signature the filter engine depends on.
Forwarder = Callable[[bytes], Optional[bytes]]
