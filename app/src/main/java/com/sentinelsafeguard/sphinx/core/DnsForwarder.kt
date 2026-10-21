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
 * the [protectUdp]/[protectTcp] hooks. This is the Android port of
 * the Python editions' forwarder (windows/src/sphinx_win/core/
 * forwarder.py, debian core/forwarder.py), with the same audited
 * validation discipline:
 *
 * - The query is forwarded unchanged over UDP/53 — default
 *   1.1.1.1, fallback 9.9.9.9 — timeout 3 seconds per upstream
 *   attempt; the fallback is tried once before giving up. If both
 *   fail, the query goes unanswered (the asking app retries).
 * - The socket is *connected* to the resolver, so the kernel only
 *   delivers datagrams that actually come from it, and a response
 *   counts as the answer only if its DNS ID matches the query's ID
 *   with the response (QR) bit set. Anything else is ignored.
 * - A truncated (TC) UDP answer is completed over TCP to the same
 *   resolver inside the same deadline (RFC 7766), exactly as the
 *   Python editions do; if TCP fails, the truncated answer is
 *   handed back and the asker retries as it sees fit.
 */
object DnsForwarder {

    const val DNS_PORT = 53
    const val UPSTREAM_TIMEOUT_MS = 3000
    const val MAX_PACKET = 32767

    val UPSTREAM_RESOLVERS = listOf("1.1.1.1", "9.9.9.9")

    fun isAnswer(data: ByteArray, length: Int, queryId: Int): Boolean =
        length >= 4 &&
            ((data[0].toInt() and 0xFF) shl 8 or (data[1].toInt() and 0xFF)) == queryId &&
            data[2].toInt() and 0x80 != 0 // QR bit

    fun isTruncated(data: ByteArray, length: Int = data.size): Boolean =
        length >= 3 && data[2].toInt() and 0x02 != 0 // TC bit

    /** Send a DNS query to the upstream resolvers; null if all fail. */
    fun forwardQuery(
        query: ByteArray,
        resolvers: List<String> = UPSTREAM_RESOLVERS,
        timeoutMs: Int = UPSTREAM_TIMEOUT_MS,
        port: Int = DNS_PORT,
        protectUdp: (DatagramSocket) -> Unit = {},
        protectTcp: (java.net.Socket) -> Unit = {},
    ): ByteArray? {
        if (query.size < 2) return null
        val queryId = ((query[0].toInt() and 0xFF) shl 8) or (query[1].toInt() and 0xFF)
        for (resolver in resolvers) {
            var socket: DatagramSocket? = null
            try {
                socket = DatagramSocket()
                protectUdp(socket) // keep our own queries out of the VPN
                socket.soTimeout = timeoutMs
                // Connected, not just addressed: the kernel then only
                // delivers datagrams that actually come from this
                // resolver, so a stray or spoofed packet from anything
                // else on the network can't be mistaken for the answer.
                socket.connect(InetSocketAddress(InetAddress.getByName(resolver), port))
                socket.send(DatagramPacket(query, query.size))
                val buffer = ByteArray(MAX_PACKET)
                val deadlineNanos = System.nanoTime() + timeoutMs * 1_000_000L
                while (true) {
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
                            return if (full != null && isAnswer(full, full.size, queryId)) {
                                full
                            } else {
                                accepted
                            }
                        }
                        return accepted
                    }
                    if (System.nanoTime() > deadlineNanos) {
                        throw SocketTimeoutException("no matching response in time")
                    }
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
        resolver: String,
        deadlineNanos: Long,
        port: Int,
        protectTcp: (java.net.Socket) -> Unit,
    ): ByteArray? {
        fun remainingMs(): Long = (deadlineNanos - System.nanoTime()) / 1_000_000L
        if (remainingMs() <= 0) return null
        var socket: java.net.Socket? = null
        try {
            socket = java.net.Socket()
            protectTcp(socket) // keep our own queries out of the VPN
            socket.connect(
                InetSocketAddress(InetAddress.getByName(resolver), port),
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
