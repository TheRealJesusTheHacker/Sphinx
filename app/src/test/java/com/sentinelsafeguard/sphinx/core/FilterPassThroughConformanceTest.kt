package com.sentinelsafeguard.sphinx.core

import java.net.DatagramPacket
import java.net.DatagramSocket
import java.net.InetAddress
import kotlin.concurrent.thread
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertTrue
import org.junit.Test

/**
 * CONFORMANCE for TUNNEL-SPEC, "The filter questions names; it
 * does not block traffic" (owner's criterion, 2026-10-23) —
 * the FILTER path.
 *
 * The failure this guards against is the real-device defect
 * the owner hit: with Sphinx on, UNLISTED names broadly failed
 * (DNS_PROBE_POSSIBLE; apps acting offline) while listed names
 * were blocked — the filter "worked too well". These tests
 * prove the opposite at JVM level: the brain's only action is
 * the DNS decision for listed names, and an unlisted name —
 * including one that merely LOOKS tracker-adjacent — resolves
 * through the shared forwarder exactly as it would without
 * Sphinx, fallback included.
 *
 * Level of proof (stated honestly): JVM, against fake local
 * upstreams in the ForwarderTest pattern, driving the same
 * [DnsPipeline] + [DnsForwarder] code the VPN service runs.
 * The Android TUN/socket plumbing around them is device-only
 * and is not claimed here.
 */
class FilterPassThroughConformanceTest {

    private fun query(name: String, id: Int = 0x1234): ByteArray {
        val out = ArrayList<Byte>()
        fun u16(v: Int) {
            out.add((v shr 8).toByte()); out.add(v.toByte())
        }
        u16(id); u16(0x0100); u16(1); u16(0); u16(0); u16(0)
        for (label in name.split('.')) {
            out.add(label.length.toByte())
            label.forEach { out.add(it.code.toByte()) }
        }
        out.add(0); u16(1); u16(1)
        return out.toByteArray()
    }

    private fun response(q: ByteArray): ByteArray {
        val r = q.copyOf()
        r[2] = (r[2].toInt() or 0x80).toByte()
        r[3] = (r[3].toInt() or 0x80).toByte()
        return r
    }

    private fun lists(): FilterLists = FilterLists(
        Blocklist(listOf("ads.example.com", "tracker.example.net")),
        Allowlist(emptyList()),
    )

    /** An answering fake upstream on [bindIp]; returns its port. */
    private fun answeringUpstream(bindIp: String): DatagramSocket {
        val socket = DatagramSocket(0, InetAddress.getByName(bindIp))
        thread(isDaemon = true) {
            try {
                while (!socket.isClosed) {
                    val buf = ByteArray(65535)
                    val packet = DatagramPacket(buf, buf.size)
                    socket.receive(packet)
                    val q = buf.copyOf(packet.length)
                    val resp = DatagramPacket(
                        response(q), response(q).size, packet.address, packet.port,
                    )
                    socket.send(resp)
                }
            } catch (e: Exception) {
                // Test over.
            }
        }
        return socket
    }

    @Test
    fun unlistedNameResolvesAndItsTrafficPassesInFilterMode() {
        // A name that looks tracker-adjacent but is NOT listed:
        // resemblance is not evidence; listing is the whole test.
        val name = "metrics-tracker-adjacent.example.org"
        assertFalse(lists().isBlocked(name))

        val upstream = answeringUpstream("127.0.0.1")
        try {
            val pipeline = DnsPipeline(lists()) { q ->
                DnsForwarder.forwardQuery(
                    q,
                    resolvers = listOf("127.0.0.1"),
                    timeoutMs = 2000,
                    port = upstream.localPort,
                )
            }
            val q = query(name)
            val result = pipeline.processQuery(q)
            assertTrue(
                "unlisted name must be forwarded, got $result",
                result is DnsPipeline.Result.Forwarded,
            )
            val forwarded = result as DnsPipeline.Result.Forwarded
            assertEquals(name, forwarded.name)
            assertFalse(forwarded.blocked)
            // The answer is the upstream's real answer — QR set,
            // same ID — not a sinkhole: A-record sinkholes carry
            // 0.0.0.0 as the answer; this response echoes the
            // query with the response bits set by the upstream.
            val parsed = DnsPacket.parse(forwarded.response, forwarded.response.size)
            assertTrue(parsed!!.isResponse)
        } finally {
            upstream.close()
        }
    }

    @Test
    fun unlistedNameResolvesViaForwarderFallbackWhenFirstUpstreamFails() {
        // The defect path, named: the first upstream attempt
        // fails (a bound socket that receives and never answers
        // — silence, the worst honest failure a resolver path
        // can meet). The unlisted name must STILL resolve, via
        // the shared forwarder's fallback to the next resolver —
        // degrade toward the network's own resolution, never
        // toward silence (TUNNEL-SPEC, commit 4d811d6).
        val silent = DatagramSocket(0, InetAddress.getByName("127.0.0.1"))
        val port = silent.localPort
        val answering = DatagramSocket(port, InetAddress.getByName("127.0.0.2"))
        val answerThread = thread(isDaemon = true) {
            try {
                val buf = ByteArray(65535)
                val packet = DatagramPacket(buf, buf.size)
                answering.receive(packet)
                val q = buf.copyOf(packet.length)
                val r = response(q)
                answering.send(DatagramPacket(r, r.size, packet.address, packet.port))
            } catch (e: Exception) {
                // Test over.
            }
        }
        try {
            val pipeline = DnsPipeline(lists()) { q ->
                DnsForwarder.forwardQuery(
                    q,
                    resolvers = listOf("127.0.0.1", "127.0.0.2"),
                    timeoutMs = 600,
                    port = port,
                )
            }
            val result = pipeline.processQuery(query("unlisted-fallback.example.org"))
            assertTrue(
                "first-upstream failure must fall back, got $result",
                result is DnsPipeline.Result.Forwarded,
            )
        } finally {
            silent.close()
            answering.close()
            answerThread.join(2000)
        }
    }

    @Test
    fun listedNameSinkholesFastWithoutTouchingTheForwarder() {
        var forwarderCalled = false
        val pipeline = DnsPipeline(lists()) {
            forwarderCalled = true
            null
        }
        val start = System.nanoTime()
        val result = pipeline.processQuery(query("ads.example.com"))
        val elapsedMs = (System.nanoTime() - start) / 1_000_000
        assertTrue(result is DnsPipeline.Result.Sinkholed)
        assertTrue((result as DnsPipeline.Result.Sinkholed).blocked)
        assertFalse("a blocked name must never wait on forwarding", forwarderCalled)
        assertTrue("sinkhole must be fast (was ${elapsedMs} ms)", elapsedMs < 2000)
    }
}
