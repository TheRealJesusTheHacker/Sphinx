package com.sentinelsafeguard.sphinx.core

import java.net.DatagramPacket
import java.net.DatagramSocket
import java.net.InetAddress
import java.net.ServerSocket
import java.util.concurrent.CountDownLatch
import java.util.concurrent.TimeUnit
import java.util.concurrent.atomic.AtomicInteger
import kotlin.concurrent.thread
import org.junit.Assert.assertArrayEquals
import org.junit.Assert.assertEquals
import org.junit.Assert.assertNotNull
import org.junit.Assert.assertNull
import org.junit.Assert.assertTrue
import org.junit.Before
import org.junit.Test

/**
 * The forwarder against fake local upstreams — the Android mirror
 * of windows/tests/test_forwarder.py: answer validation, spoof
 * discipline, the overall deadline, TCP completion of truncated
 * answers (RFC 7766), and the receive-buffer size.
 */
class ForwarderTest {

    private val loopback: InetAddress = InetAddress.getByName("127.0.0.1")
    private val deadEndA: InetAddress = InetAddress.getByName("127.0.0.2")
    private val deadEndB: InetAddress = InetAddress.getByName("127.0.0.3")

    /** Affinity is process-wide state in the forwarder; no test
     *  may inherit another test's last responder. */
    @Before
    fun resetAffinity() {
        DnsForwarder.resetLastResponder()
    }

    private fun query(name: String, id: Int = 0x1234): ByteArray {
        val out = ArrayList<Byte>()
        fun u16(v: Int) { out.add((v shr 8).toByte()); out.add(v.toByte()) }
        u16(id); u16(0x0100); u16(1); u16(0); u16(0); u16(0)
        for (label in name.split('.')) {
            out.add(label.length.toByte())
            label.forEach { out.add(it.code.toByte()) }
        }
        out.add(0); u16(1); u16(1)
        return out.toByteArray()
    }

    /** A response to [q]: QR set; optionally TC set and/or padded. */
    private fun response(q: ByteArray, truncated: Boolean = false, totalSize: Int = -1): ByteArray {
        var r = q.copyOf()
        r[2] = (r[2].toInt() or 0x80 or (if (truncated) 0x02 else 0)).toByte()
        r[3] = (r[3].toInt() or 0x80).toByte()
        if (totalSize > r.size) r = r.copyOf(totalSize)
        return r
    }

    /** UDP fake upstream on an ephemeral port; [script] runs with
     *  the socket, the received query, and the sender address/port. */
    private class FakeUdp(val socket: DatagramSocket) {
        val port: Int = socket.localPort
        fun start(script: (DatagramSocket, ByteArray, InetAddress, Int) -> Unit): Thread =
            thread(isDaemon = true) {
                try {
                    val buf = ByteArray(65535)
                    val packet = DatagramPacket(buf, buf.size)
                    socket.receive(packet)
                    script(socket, buf.copyOf(packet.length), packet.address, packet.port)
                } catch (e: Exception) {
                    // Test is over; a blocked receive ends here.
                } finally {
                    socket.close()
                }
            }
    }

    private fun fakeUdp(): FakeUdp = FakeUdp(DatagramSocket(0, InetAddress.getByName("127.0.0.1")))

    private fun sendTo(socket: DatagramSocket, bytes: ByteArray, addr: InetAddress, port: Int) {
        // Reply on a connected socket: this sandbox blocks unconnected
        // sendto() to ephemeral ports (the same note the Python tests
        // carry), while connect()+send() exercises the same path.
        if (!socket.isConnected) socket.connect(addr, port)
        socket.send(DatagramPacket(bytes, bytes.size))
    }

    @Test
    fun answerReturned() {
        val fake = fakeUdp()
        val q = query("example.com")
        fake.start { s, data, addr, port -> sendTo(s, response(data), addr, port) }
        val answer = DnsForwarder.forwardQuery(q, listOf(loopback), 2000, fake.port)
        assertNotNull(answer)
        assertEquals(0x1234, ((answer!![0].toInt() and 0xFF) shl 8) or (answer[1].toInt() and 0xFF))
    }

    @Test
    fun wrongIdDatagramIsIgnoredNotDelivered() {
        val fake = fakeUdp()
        val q = query("example.com")
        fake.start { s, data, addr, port ->
            val spoof = response(data)
            spoof[0] = 0xDE.toByte(); spoof[1] = 0xAD.toByte()
            sendTo(s, spoof, addr, port)
            sendTo(s, response(data), addr, port)
        }
        val answer = DnsForwarder.forwardQuery(q, listOf(loopback), 2000, fake.port)
        assertNotNull(answer)
        assertEquals(0x1234, ((answer!![0].toInt() and 0xFF) shl 8) or (answer[1].toInt() and 0xFF))
    }

    @Test
    fun noAnswerReturnsNullAfterFallback() {
        val fake = fakeUdp() // bound but never answers; socket stays open in the fake? close it:
        val port = fake.port
        fake.socket.close()
        val q = query("example.com")
        val answer = DnsForwarder.forwardQuery(q, listOf(loopback, loopback), 300, port)
        assertNull(answer)
    }

    // --- A-1: truncated answers are completed over TCP (RFC 7766),
    // mirroring test_forwarder.py's truncation cases. ---

    @Test
    fun truncatedAnswerCompletedOverTcp() {
        val fake = fakeUdp()
        val q = query("big.example.com")
        val full = response(q)
        fake.start { s, data, addr, port -> sendTo(s, response(data, truncated = true), addr, port) }
        val tcp = ServerSocket(fake.port, 1, InetAddress.getByName("127.0.0.1"))
        val server = thread(isDaemon = true) {
            try {
                tcp.accept().use { conn ->
                    val header = ByteArray(2)
                    var read = 0
                    val input = conn.getInputStream()
                    while (read < 2) { val n = input.read(header, read, 2 - read); if (n < 0) break; read += n }
                    val length = ((header[0].toInt() and 0xFF) shl 8) or (header[1].toInt() and 0xFF)
                    val body = ByteArray(length)
                    read = 0
                    while (read < length) { val n = input.read(body, read, length - read); if (n < 0) break; read += n }
                    assertArrayEquals(q, body)
                    val out = conn.getOutputStream()
                    out.write((full.size shr 8).toByte().toInt()); out.write(full.size.toByte().toInt())
                    out.write(full); out.flush()
                }
            } catch (e: Exception) {
                // Test end.
            } finally {
                tcp.close()
            }
        }
        val answer = DnsForwarder.forwardQuery(q, listOf(loopback), 3000, fake.port)
        server.join(2000)
        assertNotNull(answer)
        assertArrayEquals(full, answer)
    }

    @Test
    fun truncatedAnswerFallsBackWhenTcpFails() {
        val fake = fakeUdp()
        val q = query("big.example.com")
        var truncated: ByteArray? = null
        fake.start { s, data, addr, port ->
            truncated = response(data, truncated = true)
            sendTo(s, truncated!!, addr, port)
        }
        // Nothing listens on TCP at this port, so the exchange fails
        // and the truncated datagram is handed back, as in Python.
        val answer = DnsForwarder.forwardQuery(q, listOf(loopback), 3000, fake.port)
        assertNotNull(answer)
        assertArrayEquals(truncated, answer)
    }

    @Test
    fun truncatedAnswerFallsBackWhenTcpAnswerHasWrongId() {
        val fake = fakeUdp()
        val q = query("big.example.com")
        var truncated: ByteArray? = null
        fake.start { s, data, addr, port ->
            truncated = response(data, truncated = true)
            sendTo(s, truncated!!, addr, port)
        }
        val tcp = ServerSocket(fake.port, 1, InetAddress.getByName("127.0.0.1"))
        val server = thread(isDaemon = true) {
            try {
                tcp.accept().use { conn ->
                    val input = conn.getInputStream()
                    val header = ByteArray(2)
                    var read = 0
                    while (read < 2) { val n = input.read(header, read, 2 - read); if (n < 0) break; read += n }
                    val length = ((header[0].toInt() and 0xFF) shl 8) or (header[1].toInt() and 0xFF)
                    val body = ByteArray(length)
                    read = 0
                    while (read < length) { val n = input.read(body, read, length - read); if (n < 0) break; read += n }
                    val wrong = response(q)
                    wrong[0] = 0xDE.toByte(); wrong[1] = 0xAD.toByte()
                    val out = conn.getOutputStream()
                    out.write((wrong.size shr 8).toByte().toInt()); out.write(wrong.size.toByte().toInt())
                    out.write(wrong); out.flush()
                }
            } catch (e: Exception) {
            } finally {
                tcp.close()
            }
        }
        val answer = DnsForwarder.forwardQuery(q, listOf(loopback), 3000, fake.port)
        server.join(2000)
        assertArrayEquals(truncated, answer)
    }

    @Test
    fun nonTruncatedAnswerIsReturnedWithoutTcp() {
        val fake = fakeUdp()
        val q = query("example.com")
        fake.start { s, data, addr, port -> sendTo(s, response(data), addr, port) }
        // No TCP listener exists; a correct forwarder never needs one
        // for a non-truncated answer.
        val answer = DnsForwarder.forwardQuery(q, listOf(loopback), 2000, fake.port)
        assertArrayEquals(response(q), answer)
    }

    @Test
    fun isTruncatedReadsTheTcBit() {
        val q = query("example.com")
        assertTrue(DnsForwarder.isTruncated(response(q, truncated = true)))
        assertTrue(!DnsForwarder.isTruncated(response(q)))
    }

    // --- A-2: the per-attempt deadline bounds the whole wait. ---

    @Test(timeout = 15000)
    fun mismatchedDatagramCannotStretchAttemptPastDeadline() {
        val fake = fakeUdp()
        val q = query("example.com")
        fake.start { s, data, addr, port ->
            Thread.sleep(1200)
            val spoof = response(data)
            spoof[0] = 0xDE.toByte(); spoof[1] = 0xAD.toByte()
            try { sendTo(s, spoof, addr, port) } catch (e: Exception) { }
            // Then silence: a per-receive timeout would let the next
            // receive run a full timeout past the deadline.
        }
        val start = System.nanoTime()
        val answer = DnsForwarder.forwardQuery(q, listOf(loopback), 2000, fake.port)
        val elapsedMs = (System.nanoTime() - start) / 1_000_000
        assertNull(answer)
        assertTrue(
            "attempt took ${elapsedMs} ms with a 2000 ms budget and one late mismatch",
            elapsedMs < 2600,
        )
    }

    // --- A-3: the receive buffer holds a full-size DNS message. ---

    @Test
    fun receiveBufferIsFullDnsMessageSize() {
        assertEquals(65535, DnsForwarder.MAX_PACKET)
    }

    @Test
    fun oversizedUpstreamResponseIsNotSilentlyTruncated() {
        val fake = fakeUdp()
        val q = query("example.com")
        val big = response(q, totalSize = 40000)
        fake.start { s, data, addr, port -> sendTo(s, response(data, totalSize = 40000), addr, port) }
        val answer = DnsForwarder.forwardQuery(q, listOf(loopback), 3000, fake.port)
        assertNotNull(answer)
        assertEquals(40000, answer!!.size)
        assertArrayEquals(big, answer)
    }

    // --- SEV-1 (2026-10-23): the chain's floor, checked protection,
    // and affinity. On the owner's phone the shipped chain was the
    // two public resolvers and nothing else, and protect()'s result
    // was discarded: when both literals were dead ends from the
    // forwarding socket, every unlisted name failed while the
    // phone's own DNS (filter off) answered them all. These tests
    // pin the three behaviors that close that failure. ---

    @Test
    fun upstreamChainPutsPublicsFirstThenSystemServersDeduped() {
        val systemV6 = InetAddress.getByName("2001:db8::53")
        val chain = DnsForwarder.upstreamChain(
            listOf(systemV6, loopback, InetAddress.getByName("1.1.1.1")),
        )
        assertEquals(
            listOf("1.1.1.1", "9.9.9.9", "2001:db8::53", "127.0.0.1"),
            chain.map { it.hostAddress },
        )
    }

    @Test(timeout = 20000)
    fun chainFallsThroughDeadUpstreamsToTheSystemServer() {
        val fake = fakeUdp() // the "system" resolver: it answers
        val q = query("unlisted.example")
        fake.start { s, data, addr, port -> sendTo(s, response(data), addr, port) }
        // Two dead ends ahead of it in the chain — nothing listens
        // on those loopback aliases, so each attempt fails (ICMP
        // unreachable on a connected socket, or the attempt's own
        // budget) and the walk must still reach the floor.
        val chain = listOf(deadEndA, deadEndB, loopback)
        val answer = DnsForwarder.forwardQuery(q, chain, 1200, fake.port)
        assertNotNull(answer)
        assertEquals(0x1234, ((answer!![0].toInt() and 0xFF) shl 8) or (answer[1].toInt() and 0xFF))
    }

    @Test(timeout = 15000)
    fun protectRefusalSendsNothing() {
        val fake = fakeUdp()
        val arrived = CountDownLatch(1)
        fake.start { s, data, addr, port ->
            arrived.countDown()
            sendTo(s, response(data), addr, port)
        }
        val q = query("protected.example")
        val answer = DnsForwarder.forwardQuery(
            q, listOf(loopback), 1000, fake.port,
            protectUdp = { false }, // the platform refused protection
        )
        assertNull(answer)
        assertTrue(
            "a query left on a socket the platform refused to protect",
            !arrived.await(700, TimeUnit.MILLISECONDS),
        )
    }

    @Test
    fun tcpCompletionSkippedWhenTcpProtectRefused() {
        val fake = fakeUdp()
        var truncated: ByteArray? = null
        fake.start { s, data, addr, port ->
            truncated = response(data, truncated = true)
            sendTo(s, truncated!!, addr, port)
        }
        // No TCP listener exists either; with protection refused
        // the TCP exchange must not even be attempted, and the
        // truncated datagram is handed back as designed.
        val answer = DnsForwarder.forwardQuery(
            query("big.example.com"), listOf(loopback), 2000, fake.port,
            protectTcp = { false },
        )
        assertNotNull(answer)
        assertArrayEquals(truncated, answer)
    }

    @Test(timeout = 20000)
    fun lastResponderIsTriedFirstOnNextQuery() {
        val q = query("affinity.example")
        // One port, two loopback aliases: the dead end counts what
        // reaches it and never answers; the system server answers.
        val deadSocket = DatagramSocket(0, deadEndA)
        val port = deadSocket.localPort
        val deadArrivals = AtomicInteger(0)
        val deadThread = thread(isDaemon = true) {
            try {
                val buf = ByteArray(65535)
                while (true) {
                    val packet = DatagramPacket(buf, buf.size)
                    deadSocket.receive(packet)
                    deadArrivals.incrementAndGet()
                }
            } catch (e: Exception) {
                // Socket closed at test end.
            }
        }
        try {
            val good1 = FakeUdp(DatagramSocket(port, loopback))
            val t1 = good1.start { s, data, addr, p -> sendTo(s, response(data), addr, p) }
            val first = DnsForwarder.forwardQuery(q, listOf(deadEndA, loopback), 1200, port)
            t1.join(2000)
            assertNotNull(first)
            assertEquals(1, deadArrivals.get())

            // Second query, same chain: affinity must take it
            // straight to the responder — the dead end sees nothing.
            val good2 = FakeUdp(DatagramSocket(port, loopback))
            val t2 = good2.start { s, data, addr, p -> sendTo(s, response(data), addr, p) }
            val second = DnsForwarder.forwardQuery(q, listOf(deadEndA, loopback), 1200, port)
            t2.join(2000)
            assertNotNull(second)
            Thread.sleep(300) // grace for a wrongly-sent datagram to land
            assertEquals(1, deadArrivals.get())
        } finally {
            deadSocket.close()
            deadThread.join(2000)
        }
    }
}
