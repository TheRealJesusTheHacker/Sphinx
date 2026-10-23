package com.sentinelsafeguard.sphinx.core

import java.net.DatagramPacket
import java.net.DatagramSocket
import java.net.InetAddress
import java.util.concurrent.CountDownLatch
import java.util.concurrent.TimeUnit
import java.util.concurrent.atomic.AtomicReference
import kotlin.concurrent.thread
import org.junit.Assert.assertArrayEquals
import org.junit.Assert.assertEquals
import org.junit.Assert.assertNotNull
import org.junit.Assert.assertNull
import org.junit.Assert.assertTrue
import org.junit.Before
import org.junit.Test

/**
 * Fix2 hunt (2026-10-23) — the wire shapes modern Android
 * resolvers actually send, proven at the byte level: 0x20 case
 * randomization, EDNS(0) with options, HTTPS (type 65) queries,
 * queries carrying authority records — plus the forwarder's new
 * network-binding precondition, its per-resolver outcome
 * reporting, the captured-floor validation, and the diagnostics
 * probe's packet builder/summarizer.
 *
 * The base suite's queries were minimal hand-built packets with
 * none of these shapes; a parser or forwarder that mishandled
 * any of them would pass the old suite and fail on a real phone
 * in exactly the reported way — everything allowed failing at
 * once. These tests exist so that class of bug cannot come back
 * silently.
 */
class HuntCoreTest {

    private val loopback: InetAddress = InetAddress.getByName("127.0.0.1")
    private val deadEnd: InetAddress = InetAddress.getByName("127.0.0.2")

    @Before
    fun resetProcessWideState() {
        DnsForwarder.resetLastResponder()
        UpstreamHealth.reset()
    }

    // --- Packet construction: realistic shapes, byte level. ---

    /** A query with the knobs real resolvers use: mixed case
     *  (0x20), an optional EDNS OPT record, optional authority
     *  bytes appended after the question. */
    private fun realisticQuery(
        name: String,
        type: Int,
        id: Int = 0x1234,
        ednsUdpSize: Int = -1,
        ednsDoBit: Boolean = false,
        ednsOption: ByteArray? = null,
        authorityBytes: ByteArray = ByteArray(0),
    ): ByteArray {
        val out = ArrayList<Byte>()
        fun u16(v: Int) { out.add((v shr 8).toByte()); out.add(v.toByte()) }
        fun u32(v: Int) {
            out.add((v shr 24).toByte()); out.add((v shr 16).toByte())
            out.add((v shr 8).toByte()); out.add(v.toByte())
        }
        u16(id)
        u16(0x0100) // RD
        u16(1) // QDCOUNT
        u16(0) // ANCOUNT
        u16(if (authorityBytes.isEmpty()) 0 else 1) // NSCOUNT
        u16(if (ednsUdpSize >= 0) 1 else 0) // ARCOUNT
        for (label in name.split('.')) {
            out.add(label.length.toByte())
            label.forEach { out.add(it.code.toByte()) }
        }
        out.add(0)
        u16(type)
        u16(1) // IN
        authorityBytes.forEach { out.add(it) }
        if (ednsUdpSize >= 0) {
            out.add(0) // root name
            u16(41) // OPT
            u16(ednsUdpSize)
            u32(if (ednsDoBit) 0x00008000 else 0) // TTL: version/flags, DO bit
            if (ednsOption != null) {
                u16(ednsOption.size)
                ednsOption.forEach { out.add(it) }
            } else {
                u16(0)
            }
        }
        return out.toByteArray()
    }

    private fun responseTo(q: ByteArray): ByteArray {
        val r = q.copyOf()
        r[2] = (r[2].toInt() or 0x80).toByte() // QR
        r[3] = (r[3].toInt() or 0x80).toByte() // RA
        return r
    }

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
                    // Test is over.
                } finally {
                    socket.close()
                }
            }
    }

    private fun fakeUdp(): FakeUdp =
        FakeUdp(DatagramSocket(0, InetAddress.getByName("127.0.0.1")))

    private fun sendTo(socket: DatagramSocket, bytes: ByteArray, addr: InetAddress, port: Int) {
        if (!socket.isConnected) socket.connect(addr, port)
        socket.send(DatagramPacket(bytes, bytes.size))
    }

    private fun u16(data: ByteArray, offset: Int): Int =
        ((data[offset].toInt() and 0xFF) shl 8) or (data[offset + 1].toInt() and 0xFF)

    // --- 0x20 case randomization. ---

    @Test
    fun zeroX20CaseParsesLowercasedAndSinkholeEchoesExactCase() {
        val q = realisticQuery("SeNtInElSaFeGuArD.nEt", DnsPacket.TYPE_A)
        val parsed = DnsPacket.parse(q)
        assertNotNull(parsed)
        parsed!!
        assertEquals("sentinelsafeguard.net", parsed.questionName)
        val resp = parsed.buildSinkholeResponse()
        // The question section is echoed byte-for-byte, case and
        // all — a resolver matching the echoed question against
        // its 0x20-randomized query must see its own bytes back.
        assertTrue(
            q.copyOfRange(12, parsed.questionEnd)
                .contentEquals(resp.copyOfRange(12, parsed.questionEnd))
        )
    }

    // --- EDNS(0): large payloads, DO bit, options. ---

    @Test
    fun ednsQueryWithOptionParsesAndKeepsCounts() {
        // An ECS-shaped option (code 8) as options actually ride.
        val option = byteArrayOf(0, 8, 0, 4, 1, 0, 0, 0)
        val q = realisticQuery(
            "www.example.com", DnsPacket.TYPE_A,
            ednsUdpSize = 4096, ednsDoBit = true, ednsOption = option,
        )
        val parsed = DnsPacket.parse(q)
        assertNotNull(parsed)
        parsed!!
        assertEquals("www.example.com", parsed.questionName)
        assertEquals(DnsPacket.TYPE_A, parsed.questionType)
        assertEquals(1, parsed.additionalCount)
    }

    @Test
    fun ednsQueryForwardsByteForByte() {
        val fake = fakeUdp()
        val seen = AtomicReference<ByteArray>()
        fake.start { s, data, addr, port ->
            seen.set(data)
            sendTo(s, responseTo(data), addr, port)
        }
        val q = realisticQuery(
            "big.answers.example", DnsPacket.TYPE_AAAA,
            ednsUdpSize = 1232, ednsDoBit = true,
        )
        val answer = DnsForwarder.forwardQuery(q, listOf(loopback), 2000, fake.port)
        assertNotNull(answer)
        // FILTER-SPEC: allowed queries are forwarded unchanged —
        // EDNS and all. Anything less silently renegotiates the
        // asker's buffer size and DNSSEC expectations upstream.
        assertArrayEquals(q, seen.get())
    }

    @Test
    fun queryCarryingAuthorityRecordsStillParses() {
        // An authority record after the question (some resolvers
        // attach one; UPDATE-style and priming queries do). The
        // parser reads the first question and must not choke on
        // what follows it.
        val authority = byteArrayOf(0, 0, 6, 0, 1, 0, 0, 0, 60, 0, 0)
        val q = realisticQuery(
            "example.org", DnsPacket.TYPE_A, authorityBytes = authority,
        )
        val parsed = DnsPacket.parse(q)
        assertNotNull(parsed)
        parsed!!
        assertEquals("example.org", parsed.questionName)
        assertEquals(1, parsed.authorityCount)
    }

    // --- HTTPS / SVCB (type 65): the query type Android's
    // resolver issues alongside A/AAAA for modern apps. ---

    @Test
    fun httpsType65BlockedNameGetsNoErrorWithNoAnswers() {
        val q = realisticQuery("ads.example.com", 65)
        val parsed = DnsPacket.parse(q)
        assertNotNull(parsed)
        val resp = parsed!!.buildSinkholeResponse()
        assertEquals(0, u16(resp, 2) and 0x000F) // NOERROR
        assertEquals(0, u16(resp, 6)) // ANCOUNT 0 — the spec's form
        assertEquals(parsed.questionEnd, resp.size)
    }

    @Test
    fun httpsType65AllowedNameForwardsByteForByte() {
        val fake = fakeUdp()
        val seen = AtomicReference<ByteArray>()
        fake.start { s, data, addr, port ->
            seen.set(data)
            sendTo(s, responseTo(data), addr, port)
        }
        val q = realisticQuery("sentinelsafeguard.net", 65, ednsUdpSize = 1232)
        val answer = DnsForwarder.forwardQuery(q, listOf(loopback), 2000, fake.port)
        assertNotNull(answer)
        assertArrayEquals(q, seen.get())
    }

    // --- Network binding: the floor's reachability precondition. ---

    @Test(timeout = 15000)
    fun bindRefusalSendsNothingAndReportsBindRefused() {
        val fake = fakeUdp()
        val arrived = CountDownLatch(1)
        fake.start { s, data, addr, port ->
            arrived.countDown()
            sendTo(s, responseTo(data), addr, port)
        }
        val outcomes = ArrayList<UpstreamHealth.Outcome>()
        val answer = DnsForwarder.forwardQuery(
            realisticQuery("carrier-only.example", DnsPacket.TYPE_A),
            listOf(loopback), 1000, fake.port,
            bindUdp = { _, _ -> false }, // the pin was refused
            onOutcome = { _, outcome, _ -> outcomes.add(outcome) },
        )
        assertNull(answer)
        assertEquals(listOf(UpstreamHealth.Outcome.BIND_REFUSED), outcomes)
        assertTrue(
            "a query left on a socket that could not be pinned to its network",
            !arrived.await(700, TimeUnit.MILLISECONDS),
        )
    }

    @Test(timeout = 20000)
    fun bindIsOfferedPerResolverAndOutcomesFollowTheWalk() {
        val fake = fakeUdp()
        fake.start { s, data, addr, port -> sendTo(s, responseTo(data), addr, port) }
        val bound = ArrayList<InetAddress>()
        val outcomes = ArrayList<Pair<InetAddress, UpstreamHealth.Outcome>>()
        val answer = DnsForwarder.forwardQuery(
            realisticQuery("walk.example", DnsPacket.TYPE_A),
            listOf(deadEnd, loopback), 600, fake.port,
            bindUdp = { _, resolver -> bound.add(resolver); true },
            onOutcome = { resolver, outcome, _ -> outcomes.add(resolver to outcome) },
        )
        assertNotNull(answer)
        // The dead end is bound and tried first, times out, and
        // the walk reaches the answering floor — each step
        // reported, in order, for the diagnostics screen.
        assertEquals(listOf(deadEnd, loopback), bound)
        assertEquals(
            listOf(
                deadEnd to UpstreamHealth.Outcome.TIMED_OUT_OR_ERROR,
                loopback to UpstreamHealth.Outcome.ANSWERED,
            ),
            outcomes,
        )
    }

    @Test(timeout = 15000)
    fun protectRefusalReportsProtectRefused() {
        val outcomes = ArrayList<UpstreamHealth.Outcome>()
        val answer = DnsForwarder.forwardQuery(
            realisticQuery("protected.example", DnsPacket.TYPE_A),
            listOf(loopback), 1000, 53,
            protectUdp = { false },
            onOutcome = { _, outcome, _ -> outcomes.add(outcome) },
        )
        assertNull(answer)
        assertEquals(listOf(UpstreamHealth.Outcome.PROTECT_REFUSED), outcomes)
    }

    // --- The captured floor: validation and scope. ---

    @Test
    fun systemDnsFilterDropsUnusableKeepsCarrierShapes() {
        val anyLocal = InetAddress.getByName("0.0.0.0")
        val loop = InetAddress.getByName("127.0.0.1")
        val selfV4 = InetAddress.getByName("10.10.10.10")
        val selfV6 = InetAddress.getByName("fd00:10:10::10")
        val linkLocal = InetAddress.getByName("fe80::1")
        val nat64 = InetAddress.getByName("64:ff9b::101:101")
        val ula = InetAddress.getByName("fd00::53")
        val home = InetAddress.getByName("192.168.1.1")
        val usable = SystemDnsFilter.usable(
            listOf(anyLocal, loop, selfV4, selfV6, linkLocal, nat64, ula, home, home),
        )
        assertEquals(listOf(linkLocal, nat64, ula, home), usable)
        assertEquals(
            "link-local (this network only)",
            SystemDnsFilter.scopeNote(linkLocal),
        )
        assertEquals(
            "NAT64 translated (carrier IPv6 network)",
            SystemDnsFilter.scopeNote(nat64),
        )
        assertEquals("private IPv6 (ULA)", SystemDnsFilter.scopeNote(ula))
        assertEquals("private address", SystemDnsFilter.scopeNote(home))
        assertEquals(
            "IPv4",
            SystemDnsFilter.scopeNote(InetAddress.getByName("1.1.1.1")),
        )
    }

    // --- The diagnostics probe's packets. ---

    @Test
    fun probeQueryIsARealResolverQuery() {
        val q = DnsProbe.buildQuery("sentinelsafeguard.net", DnsPacket.TYPE_A, 0x4242)
        assertNotNull(q)
        val parsed = DnsPacket.parse(q!!)
        assertNotNull(parsed)
        parsed!!
        assertEquals(0x4242, parsed.id)
        assertEquals("sentinelsafeguard.net", parsed.questionName)
        assertEquals(1, parsed.additionalCount)
        // The OPT record itself: root name, type 41, class 1232.
        var p = parsed.questionEnd
        assertEquals(0, q[p].toInt()); p += 1
        assertEquals(41, u16(q, p)); p += 2
        assertEquals(DnsProbe.PROBE_EDNS_UDP_SIZE, u16(q, p))
    }

    @Test
    fun probeSummaryReadsAnswerForms() {
        // A response carrying one A answer (93.184.216.34).
        val query = realisticQuery("example.com", DnsPacket.TYPE_A)
        val resp = ArrayList<Byte>()
        fun u16v(v: Int) { resp.add((v shr 8).toByte()); resp.add(v.toByte()) }
        fun u32v(v: Int) {
            resp.add((v shr 24).toByte()); resp.add((v shr 16).toByte())
            resp.add((v shr 8).toByte()); resp.add(v.toByte())
        }
        val head = query.copyOf(12)
        head[2] = (0x81).toByte(); head[3] = (0x80).toByte() // QR RD / RA
        head.forEach { resp.add(it) }
        resp[6] = 0; resp[7] = 1 // ANCOUNT 1 (bytes 6-7 of the packet)
        query.copyOfRange(12, query.size).forEach { resp.add(it) }
        resp.add(0xC0.toByte()); resp.add(0x0C) // name pointer
        u16v(1); u16v(1); u32v(300); u16v(4) // A IN TTL RDLENGTH
        listOf(93, 184, 216, 34).forEach { resp.add(it.toByte()) }
        val summary = DnsProbe.summarizeAnswer(resp.toByteArray())
        assertNotNull(summary)
        summary!!
        assertEquals("NOERROR", summary.rcodeName)
        assertEquals(1, summary.answerCount)
        assertEquals("93.184.216.34", summary.firstAddress)

        // NXDOMAIN: same header discipline, RCODE 3, no answers.
        val nx = query.copyOf()
        nx[2] = (0x81).toByte(); nx[3] = (0x83).toByte()
        val nxSummary = DnsProbe.summarizeAnswer(nx)
        assertNotNull(nxSummary)
        assertEquals("NXDOMAIN", nxSummary!!.rcodeName)
        assertEquals(0, nxSummary.answerCount)
        assertNull(nxSummary.firstAddress)

        // NODATA: NOERROR with an empty answer section.
        val nodata = query.copyOf()
        nodata[2] = (0x81).toByte(); nodata[3] = (0x80).toByte()
        val ndSummary = DnsProbe.summarizeAnswer(nodata)
        assertNotNull(ndSummary)
        assertEquals("NOERROR", ndSummary!!.rcodeName)
        assertEquals(0, ndSummary.answerCount)
        assertNull(ndSummary.firstAddress)
    }

    // --- Upstream health memory. ---

    @Test
    fun upstreamHealthKeepsTheLastOutcomePerResolver() {
        val a = InetAddress.getByName("1.1.1.1")
        val b = InetAddress.getByName("9.9.9.9")
        UpstreamHealth.record(a, UpstreamHealth.Outcome.ANSWERED, 1000L, 42L)
        UpstreamHealth.record(b, UpstreamHealth.Outcome.TIMED_OUT_OR_ERROR, 1001L)
        assertEquals(
            UpstreamHealth.Outcome.ANSWERED,
            UpstreamHealth.lastOutcome(a)?.outcome,
        )
        assertEquals(42L, UpstreamHealth.lastOutcome(a)?.rttMillis)
        assertEquals(
            UpstreamHealth.Outcome.TIMED_OUT_OR_ERROR,
            UpstreamHealth.lastOutcome(b)?.outcome,
        )
        UpstreamHealth.record(a, UpstreamHealth.Outcome.TIMED_OUT_OR_ERROR, 2000L)
        assertEquals(
            UpstreamHealth.Outcome.TIMED_OUT_OR_ERROR,
            UpstreamHealth.lastOutcome(a)?.outcome,
        )
    }
}
