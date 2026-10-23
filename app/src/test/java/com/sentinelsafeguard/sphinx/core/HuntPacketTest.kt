package com.sentinelsafeguard.sphinx.core

import java.net.InetAddress
import org.junit.Assert.assertArrayEquals
import org.junit.Assert.assertEquals
import org.junit.Assert.assertNotNull
import org.junit.Assert.assertNull
import org.junit.Assert.assertTrue
import org.junit.Test

/**
 * Fix2 hunt (2026-10-23) — the transport families the base
 * filter could not hear: DNS arriving over IPv6 (finding F1)
 * and DNS attempted over TCP (finding F4). Byte-level packets,
 * parsed and answered by the pure core exactly as the VPN
 * service's packet loop drives it.
 */
class HuntPacketTest {

    private val v6Dns = InetAddress.getByName("fd00:10:10::10").address // 16 bytes
    private val v6Client = InetAddress.getByName("fd00:10:10::5").address
    private val v4Dns = byteArrayOf(10, 10, 10, 10)
    private val v4Client = byteArrayOf(10, 10, 10, 5)

    private fun u16(data: ByteArray, offset: Int): Int =
        ((data[offset].toInt() and 0xFF) shl 8) or (data[offset + 1].toInt() and 0xFF)

    private fun dnsQuery(name: String, type: Int, id: Int = 0x1234): ByteArray {
        val out = ArrayList<Byte>()
        fun u16v(v: Int) { out.add((v shr 8).toByte()); out.add(v.toByte()) }
        u16v(id); u16v(0x0100); u16v(1); u16v(0); u16v(0); u16v(0)
        for (label in name.split('.')) {
            out.add(label.length.toByte())
            label.forEach { out.add(it.code.toByte()) }
        }
        out.add(0); u16v(type); u16v(1)
        return out.toByteArray()
    }

    /** An IPv6/UDP packet (checksum left zero — the parser
     *  reads headers, it does not verify checksums). */
    private fun v6UdpPacket(
        src: ByteArray, dst: ByteArray, srcPort: Int, dstPort: Int, payload: ByteArray,
    ): ByteArray {
        val udpLength = 8 + payload.size
        val out = ByteArray(40 + udpLength)
        out[0] = 0x60
        DnsPacket.putU16(out, 4, udpLength)
        out[6] = 17 // UDP
        out[7] = 64
        src.copyInto(out, 8)
        dst.copyInto(out, 24)
        DnsPacket.putU16(out, 40, srcPort)
        DnsPacket.putU16(out, 42, dstPort)
        DnsPacket.putU16(out, 44, udpLength)
        payload.copyInto(out, 48)
        return out
    }

    /** Recompute a checksum over a whole segment INCLUDING its
     *  checksum field: a correctly checksummed segment sums to
     *  zero under the same algorithm. */
    private fun checksumVerifies(
        src: ByteArray, dst: ByteArray, protocol: Int, segment: ByteArray,
    ): Boolean {
        val pseudo = ByteArray(if (src.size == 16) 40 else 12)
        src.copyInto(pseudo, 0)
        dst.copyInto(pseudo, src.size)
        if (src.size == 16) {
            DnsPacket.putU32(pseudo, 32, segment.size)
            pseudo[39] = protocol.toByte()
        } else {
            pseudo[8] = 0
            pseudo[9] = protocol.toByte()
            DnsPacket.putU16(pseudo, 10, segment.size)
        }
        var sum = IpUdpPacket.checksum(pseudo, 0, pseudo.size, checksumSeed = 0, final = false)
        sum = IpUdpPacket.checksum(segment, 0, segment.size, sum, final = true)
        return sum == 0
    }

    // --- IPv6 transport. ---

    @Test
    fun ipv6DnsPacketParses() {
        val payload = dnsQuery("example.com", DnsPacket.TYPE_AAAA)
        val packet = v6UdpPacket(v6Client, v6Dns, 53111, 53, payload)
        val parsed = Ip6UdpPacket.parse(packet)
        assertNotNull(parsed)
        parsed!!
        assertEquals(53111, parsed.sourcePort)
        assertEquals(53, parsed.destPort)
        assertArrayEquals(v6Dns, parsed.destAddress)
        assertEquals(payload.size, parsed.payloadLength)
        assertArrayEquals(
            payload,
            packet.copyOfRange(parsed.payloadOffset, parsed.payloadOffset + parsed.payloadLength),
        )
    }

    @Test
    fun ipv6RejectsNonUdpAndShortPackets() {
        val payload = dnsQuery("example.com", DnsPacket.TYPE_A)
        val tcp = v6UdpPacket(v6Client, v6Dns, 1234, 53, payload)
        tcp[6] = 6 // TCP, not UDP
        assertNull(Ip6UdpPacket.parse(tcp))
        assertNull(Ip6UdpPacket.parse(ByteArray(30)))
        // An IPv4 packet is not an IPv6 packet.
        val v4 = ByteArray(28 + payload.size)
        v4[0] = 0x45
        DnsPacket.putU16(v4, 2, v4.size)
        v4[9] = 17
        v4Client.copyInto(v4, 12)
        v4Dns.copyInto(v4, 16)
        DnsPacket.putU16(v4, 20, 1234)
        DnsPacket.putU16(v4, 22, 53)
        DnsPacket.putU16(v4, 24, 8 + payload.size)
        payload.copyInto(v4, 28)
        assertNull(Ip6UdpPacket.parse(v4))
    }

    @Test
    fun ipv6ResponseSwapsAndChecksumsVerify() {
        val payload = dnsQuery("example.com", DnsPacket.TYPE_A)
        val request = v6UdpPacket(v6Client, v6Dns, 40000, 53, payload)
        val parsed = Ip6UdpPacket.parse(request)!!
        val responsePayload = DnsPacket.parse(payload)!!.buildSinkholeResponse()
        val response = Ip6UdpPacket.buildResponse(parsed, responsePayload)

        val back = Ip6UdpPacket.parse(response)
        assertNotNull(back)
        back!!
        assertEquals(53, back.sourcePort)
        assertEquals(40000, back.destPort)
        assertArrayEquals(v6Dns, back.sourceAddress)
        assertArrayEquals(v6Client, back.destAddress)
        assertArrayEquals(
            responsePayload,
            response.copyOfRange(back.payloadOffset, back.payloadOffset + back.payloadLength),
        )
        // IPv6 has no optional checksum: what we computed must verify.
        val segment = response.copyOfRange(40, response.size)
        assertTrue(checksumVerifies(v6Dns, v6Client, 17, segment))
    }

    @Test
    fun sinkholeEndToEndOverIpv6Transport() {
        // The whole FILTER-mode v6 path at packet level: query in
        // over IPv6 -> blocked -> sinkhole -> response out over
        // IPv6, carrying the sinkhole bytes untouched.
        val query = dnsQuery("ads.example.com", DnsPacket.TYPE_AAAA)
        val packet = v6UdpPacket(v6Client, v6Dns, 50505, 53, query)
        val ip = Ip6UdpPacket.parse(packet)!!
        val payload = packet.copyOfRange(ip.payloadOffset, ip.payloadOffset + ip.payloadLength)
        val dns = DnsPacket.parse(payload)!!
        assertTrue(dns.questionName == "ads.example.com")
        val response = Ip6UdpPacket.buildResponse(ip, dns.buildSinkholeResponse())
        val back = Ip6UdpPacket.parse(response)!!
        val answerBytes = response.copyOfRange(
            back.payloadOffset, back.payloadOffset + back.payloadLength,
        )
        val answer = DnsPacket.parse(answerBytes)!!
        assertEquals(0x1234, answer.id)
        assertTrue(answer.isResponse)
        assertEquals(1, u16(answerBytes, 6)) // one AAAA answer (::)
    }

    // --- TCP: the reset, and only the reset. ---

    private fun v4TcpPacket(
        src: ByteArray, dst: ByteArray, srcPort: Int, dstPort: Int,
        seq: Int, ack: Int, flags: Int, payload: ByteArray = ByteArray(0),
    ): ByteArray {
        val total = 20 + 20 + payload.size
        val out = ByteArray(total)
        out[0] = 0x45
        DnsPacket.putU16(out, 2, total)
        out[8] = 64
        out[9] = 6 // TCP
        src.copyInto(out, 12)
        dst.copyInto(out, 16)
        DnsPacket.putU16(out, 20, srcPort)
        DnsPacket.putU16(out, 22, dstPort)
        IpTcpPacket.putU32(out, 24, seq)
        IpTcpPacket.putU32(out, 28, ack)
        out[32] = (5 shl 4).toByte()
        out[33] = flags.toByte()
        payload.copyInto(out, 40)
        return out
    }

    @Test
    fun tcpSynToTheVirtualDnsGetsAResetAck() {
        val syn = v4TcpPacket(
            v4Client, v4Dns, 44444, 53,
            seq = 1000, ack = 0, flags = IpTcpPacket.FLAG_SYN,
        )
        val parsed = IpTcpPacket.parse(syn)
        assertNotNull(parsed)
        val reset = IpTcpPacket.buildReset(parsed!!)
        val back = IpTcpPacket.parse(reset)
        assertNotNull(back)
        back!!
        // RFC 9293 reset for a SYN: RST+ACK, sequence 0,
        // acknowledging the SYN (seq + 1).
        assertEquals(IpTcpPacket.FLAG_RST or IpTcpPacket.FLAG_ACK, back.flags)
        assertEquals(0, back.sequence)
        assertEquals(1001, back.acknowledgment)
        assertEquals(53, back.sourcePort)
        assertEquals(44444, back.destPort)
        assertArrayEquals(v4Dns, back.sourceAddress)
        assertEquals(0, back.payloadLength)
        // Both checksums on the crafted packet must verify.
        assertEquals(0, IpUdpPacket.checksum(reset, 0, 20))
        val segment = reset.copyOfRange(20, reset.size)
        assertTrue(checksumVerifies(v4Dns, v4Client, 6, segment))
    }

    @Test
    fun tcpSegmentCarryingAckGetsABareReset() {
        val data = v4TcpPacket(
            v4Client, v4Dns, 44444, 53,
            seq = 500, ack = 9000,
            flags = IpTcpPacket.FLAG_ACK or 0x08, // ACK + PSH
            payload = ByteArray(20),
        )
        val parsed = IpTcpPacket.parse(data)!!
        assertEquals(20, parsed.payloadLength)
        val reset = IpTcpPacket.buildReset(parsed)
        val back = IpTcpPacket.parse(reset)!!
        // With ACK present the reset takes its sequence from the
        // segment's acknowledgment and carries no ACK of its own.
        assertEquals(IpTcpPacket.FLAG_RST, back.flags)
        assertEquals(9000, back.sequence)
    }

    @Test
    fun udpPacketsDoNotParseAsTcp() {
        val payload = dnsQuery("example.com", DnsPacket.TYPE_A)
        val udp = ByteArray(28 + payload.size)
        udp[0] = 0x45
        DnsPacket.putU16(udp, 2, udp.size)
        udp[9] = 17
        v4Client.copyInto(udp, 12)
        v4Dns.copyInto(udp, 16)
        DnsPacket.putU16(udp, 20, 1234)
        DnsPacket.putU16(udp, 22, 53)
        DnsPacket.putU16(udp, 24, 8 + payload.size)
        payload.copyInto(udp, 28)
        assertNull(IpTcpPacket.parse(udp))
    }
}
