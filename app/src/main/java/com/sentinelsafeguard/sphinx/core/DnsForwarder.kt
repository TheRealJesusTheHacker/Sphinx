package com.sentinelsafeguard.sphinx.core

import java.net.DatagramPacket
import java.net.DatagramSocket
import java.net.InetAddress
import java.net.InetSocketAddress
import java.net.SocketTimeoutException

/**
 * Forwarding of allowed queries to an upstream resolver —
 * FILTER-SPEC, "Forwarding behavior (allowed queries)". Pure
 * Kotlin/Java — no Android APIs — so this code is JVM-testable;
 * the VPN service supplies its VpnService.protect() calls through
 * the [protectUdp]/[protectTcp] hooks, which report the platform's
 * verdict back. This is the Android port of the Python editions'
 * forwarder (windows/src/sphinx_win/core/forwarder.py, debian
 * core/forwarder.py), with the same audited validation discipline:
 *
 * - The query is forwarded unchanged over UDP/53 to a chain of
 *   upstreams — the public resolvers 1.1.1.1 and 9.9.9.9 first,
 *   then the device's own DNS servers (captured by the service
 *   when the filter engaged) as the floor — timeout 3 seconds
 *   per upstream attempt. Only when every upstream in the chain
 *   has failed does the query go unanswered (the asking app
 *   retries). The chain exists under the governing rule: an
 *   allowed query must never fail merely because the public
 *   upstreams are unreachable on the current network — the path
 *   degrades toward the network's own resolution, never toward
 *   silence. (The 2026-10-23 SEV-1: the chain had no floor, so on
 *   a network where both public literals were dead ends from the
 *   forwarding socket, every unlisted name failed while the
 *   phone's own DNS — Sphinx off — answered them all.)
 * - The socket is *connected* to the resolver, so the kernel only
 *   delivers datagrams that actually come from it, and a response
 *   counts as the answer only if its DNS ID matches the query's ID
 *   with the response (QR) bit set. Anything else is ignored.
 * - Protection is a checked precondition, not an assumption:
 *   if the platform refuses to protect a forwarding socket, the
 *   socket is not used. An unprotected query would loop back
 *   into the filter's own TUN and die silently there (its
 *   destination is not the virtual DNS address, so the packet
 *   handler drops it) — the one failure this design exists to
 *   prevent must not be reachable by ignoring a return value.
 * - The resolver that last answered is tried first on the next
 *   query, so a network where the head of the chain is dead
 *   converges on the working resolver instead of paying the dead
 *   attempts' timeouts for every name.
 * - The 3-second budget covers the whole wait, not each datagram:
 *   the receive timeout is re-armed to the remaining budget before
 *   every receive, so mismatched datagrams cannot stretch it.
 * - A truncated (TC) UDP answer is completed over TCP to the same
 *   resolver inside the same deadline (RFC 7766), exactly as the
 *   Python editions do; if TCP fails, the truncated answer is
 *   handed back and the asker retries as it sees fit.
 */
object DnsForwarder {

    const val DNS_PORT = 53
    const val UPSTREAM_TIMEOUT_MS = 3000
    /** A full-size DNS message: the largest a UDP datagram can be.
     *  A smaller receive buffer would silently truncate an
     *  oversized upstream answer and forward the corrupt remainder
     *  as if it were genuine — the Python editions use 65,535 too. */
    const val MAX_PACKET = 65535

    /** The public head of every upstream chain. Numeric literals,
     *  so building the addresses never performs a lookup. */
    val UPSTREAM_RESOLVERS: List<InetAddress> = listOf(
        InetAddress.getByName("1.1.1.1"),
        InetAddress.getByName("9.9.9.9"),
    )

    /** No chain runs longer than this: two public resolvers plus
     *  up to four of the device's own. A longer chain would stack
     *  per-attempt timeouts past what any asker will wait for. */
    private const val MAX_CHAIN = 6

    /**
     * The upstream chain for one query: the public resolvers first
     * (the design's chosen head), then the device's own DNS servers
     * in the order the platform reported them, duplicates removed.
     * The device's own servers are the floor — the resolvers that
     * were answering this device the moment before the filter
     * engaged.
     */
    fun upstreamChain(systemServers: List<InetAddress>): List<InetAddress> {
        val chain = LinkedHashSet<InetAddress>()
        chain.addAll(UPSTREAM_RESOLVERS)
        chain.addAll(systemServers)
        return chain.take(MAX_CHAIN)
    }

    /** The resolver that answered most recently, tried first on
     *  the next query (see the class doc). Volatile and benign
     *  under races: a stale read only costs the chain's ordinary
     *  order for one query. */
    @Volatile
    private var lastResponder: InetAddress? = null

    /** Test hook: affinity is process-wide, so tests reset it. */
    internal fun resetLastResponder() {
        lastResponder = null
    }

    fun isAnswer(data: ByteArray, length: Int, queryId: Int): Boolean =
        length >= 4 &&
            ((data[0].toInt() and 0xFF) shl 8 or (data[1].toInt() and 0xFF)) == queryId &&
            data[2].toInt() and 0x80 != 0 // QR bit

    fun isTruncated(data: ByteArray, length: Int = data.size): Boolean =
        length >= 3 && data[2].toInt() and 0x02 != 0 // TC bit

    /** Send a DNS query to the upstream chain; null if all fail.
     *  The [protectUdp]/[protectTcp] hooks must return the
     *  platform's verdict: false means the socket could not be
     *  protected from the VPN, and it is then not used at all. */
    fun forwardQuery(
        query: ByteArray,
        resolvers: List<InetAddress> = UPSTREAM_RESOLVERS,
        timeoutMs: Int = UPSTREAM_TIMEOUT_MS,
        port: Int = DNS_PORT,
        protectUdp: (DatagramSocket) -> Boolean = { true },
        protectTcp: (java.net.Socket) -> Boolean = { true },
    ): ByteArray? {
        if (query.size < 2) return null
        val queryId = ((query[0].toInt() and 0xFF) shl 8) or (query[1].toInt() and 0xFF)
        // Affinity: the resolver that answered last time goes
        // first; the rest keep their chain order behind it.
        val preferred = lastResponder
        val ordered =
            if (preferred != null && resolvers.contains(preferred)) {
                listOf(preferred) + resolvers.filter { it != preferred }
            } else {
                resolvers
            }
        for (resolver in ordered) {
            var socket: DatagramSocket? = null
            try {
                socket = DatagramSocket()
                if (!protectUdp(socket)) {
                    // Protection refused: sending anyway would
                    // loop the query back into the filter's own
                    // TUN, where it dies silently. Skip this
                    // resolver without putting a byte on the wire;
                    // the finally below closes the socket.
                    continue
                }
                socket.soTimeout = timeoutMs
                // Connected, not just addressed: the kernel then only
                // delivers datagrams that actually come from this
                // resolver, so a stray or spoofed packet from anything
                // else on the network can't be mistaken for the answer.
                socket.connect(InetSocketAddress(resolver, port))
                socket.send(DatagramPacket(query, query.size))
                val buffer = ByteArray(MAX_PACKET)
                val deadlineNanos = System.nanoTime() + timeoutMs * 1_000_000L
                while (true) {
                    // The budget covers the whole wait, not each
                    // datagram: soTimeout is per-receive, so re-arm
                    // it to the *remaining* budget before every
                    // receive — a stream of mismatched datagrams
                    // then cannot stretch this attempt past the
                    // deadline (the Python editions' discipline).
                    val remainingMs =
                        (deadlineNanos - System.nanoTime()) / 1_000_000L
                    if (remainingMs <= 0) {
                        throw SocketTimeoutException("no matching response in time")
                    }
                    socket.soTimeout =
                        remainingMs.coerceAtMost(Int.MAX_VALUE.toLong()).toInt()
                            .coerceAtLeast(1)
                    val response = DatagramPacket(buffer, buffer.size)
                    socket.receive(response)
                    if (isAnswer(buffer, response.length, queryId)) {
                        val accepted = buffer.copyOf(response.length)
                        if (isTruncated(accepted)) {
                            // Truncated answers are completed over
                            // TCP, like every stub resolver does
                            // (RFC 7766); if TCP fails, hand back
                            // the truncated answer and let the
                            // asker retry as it sees fit. In FILTER
                            // mode the resolver's own TCP retry
                            // would enter the TUN as a TCP packet
                            // and be dropped, so completing here is
                            // the only way a large answer arrives.
                            val full = tcpExchange(
                                query, resolver, deadlineNanos, port, protectTcp,
                            )
                            lastResponder = resolver
                            return if (full != null && isAnswer(full, full.size, queryId)) {
                                full
                            } else {
                                accepted
                            }
                        }
                        lastResponder = resolver
                        return accepted
                    }
                    // Not our answer: ignore it and keep waiting —
                    // the re-armed timeout above bounds the whole wait.
                }
            } catch (e: Exception) {
                // Timeout or socket error: try the next resolver.
            } finally {
                socket?.close()
            }
        }
        return null
    }

    /**
     * Redo a truncated query over TCP (RFC 7766): length-prefixed
     * query, length-prefixed answer, same overall deadline as the
     * UDP attempt that produced the truncated answer. Null on any
     * failure — the caller falls back to the truncated datagram.
     */
    private fun tcpExchange(
        query: ByteArray,
        resolver: InetAddress,
        deadlineNanos: Long,
        port: Int,
        protectTcp: (java.net.Socket) -> Boolean,
    ): ByteArray? {
        fun remainingMs(): Long = (deadlineNanos - System.nanoTime()) / 1_000_000L
        if (remainingMs() <= 0) return null
        var socket: java.net.Socket? = null
        try {
            socket = java.net.Socket()
            if (!protectTcp(socket)) {
                // Unprotected, this exchange would loop back into
                // the filter like any other — refuse it; the caller
                // hands back the truncated UDP answer instead.
                return null
            }
            socket.connect(
                InetSocketAddress(resolver, port),
                remainingMs().coerceAtLeast(1).coerceAtMost(Int.MAX_VALUE.toLong()).toInt(),
            )
            val out = socket.getOutputStream()
            out.write((query.size shr 8).toByte().toInt())
            out.write(query.size.toByte().toInt())
            out.write(query)
            out.flush()
            val header = recvExactly(socket, 2, deadlineNanos) ?: return null
            val length = ((header[0].toInt() and 0xFF) shl 8) or (header[1].toInt() and 0xFF)
            if (length <= 0) return null
            return recvExactly(socket, length, deadlineNanos)
        } catch (e: Exception) {
            return null
        } finally {
            try {
                socket?.close()
            } catch (e: Exception) {
                // Already gone.
            }
        }
    }

    /** Read exactly [count] bytes before [deadlineNanos], re-arming
     *  the socket timeout to the remaining budget before each read
     *  (the Python editions' _recv_exactly discipline). */
    private fun recvExactly(
        socket: java.net.Socket,
        count: Int,
        deadlineNanos: Long,
    ): ByteArray? {
        val chunks = ByteArray(count)
        var read = 0
        val input = socket.getInputStream()
        while (read < count) {
            val remainingMs = (deadlineNanos - System.nanoTime()) / 1_000_000L
            if (remainingMs <= 0) return null
            socket.soTimeout =
                remainingMs.coerceAtMost(Int.MAX_VALUE.toLong()).toInt().coerceAtLeast(1)
            val n = try {
                input.read(chunks, read, count - read)
            } catch (e: Exception) {
                return null
            }
            if (n < 0) return null
            read += n
        }
        return chunks
    }
}
