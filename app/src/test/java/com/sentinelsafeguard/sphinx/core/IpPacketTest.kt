package com.sentinelsafeguard.sphinx.core

import org.junit.Assert.assertEquals
import org.junit.Assert.assertNotNull
import org.junit.Assert.assertNull
import org.junit.Assert.assertTrue
import org.junit.Test

class IpPacketTest {

    /** Build an IPv4/UDP packet by hand (checksums left zero — parser doesn't need them). */
    private fun udpPacket(
        src: ByteArray = byteArrayOf(10, 0, 0, 5),
        dst: ByteArray = byteArrayOf(10, 10, 10, 10),
        srcPort: Int = 53111,
        dstPort: Int = 53,
        payload: ByteArray = byteArrayOf(1, 2, 3, 4),
        protocol: Int = 17,
    ): ByteArray {
        val total = 20 + 8 + payload.size
        val out = ByteArray(total)
        out[0] = 0x45
        out[2] = (total shr 8).toByte(); out[3] = total.toByte()
        out[8] = 64
        out[9] = protocol.toByte()
        src.copyInto(out, 12)
        dst.copyInto(out, 16)
        out[20] = (srcPort shr 8).toByte(); out[21] = srcPort.toByte()
        out[22] = (dstPort shr 8).toByte(); out[23] = dstPort.toByte()
        val udpLen = 8 + payload.size
        out[24] = (udpLen shr 8).toByte(); out[25] = udpLen.toByte()
        payload.copyInto(out, 28)
        return out
    }

    @Test
    fun parsesUdpPacket() {
        val parsed = IpUdpPacket.parse(udpPacket(payload = byteArrayOf(9, 8, 7)))
        assertNotNull(parsed)
        parsed!!
        assertEquals(53111, parsed.sourcePort)
        assertEquals(53, parsed.destPort)
        assertEquals(28, parsed.payloadOffset)
        assertEquals(3, parsed.payloadLength)
        assertTrue(parsed.destAddress.contentEquals(byteArrayOf(10, 10, 10, 10)))
    }

    @Test
    fun rejectsNonUdpAndNonIpv4() {
        assertNull(IpUdpPacket.parse(udpPacket(protocol = 6))) // TCP
        val v6 = udpPacket(); v6[0] = 0x60
        assertNull(IpUdpPacket.parse(v6))
        assertNull(IpUdpPacket.parse(ByteArray(10)))
    }

    @Test
    fun responseSwapsEndpointsAndChecksumsValidate() {
        val request = udpPacket(payload = byteArrayOf(1, 1, 1, 1))
        val parsed = IpUdpPacket.parse(request)!!
        val responsePayload = byteArrayOf(5, 6, 7, 8, 9)
        val response = IpUdpPacket.buildResponse(parsed, responsePayload)

        val reparsed = IpUdpPacket.parse(response)
        assertNotNull(reparsed)
        reparsed!!
        assertEquals(53, reparsed.sourcePort)
        assertEquals(53111, reparsed.destPort)
        assertTrue(reparsed.sourceAddress.contentEquals(byteArrayOf(10, 10, 10, 10)))
        assertTrue(reparsed.destAddress.contentEquals(byteArrayOf(10, 0, 0, 5)))
        assertTrue(
            response.copyOfRange(reparsed.payloadOffset, reparsed.payloadOffset + reparsed.payloadLength)
                .contentEquals(responsePayload)
        )

        // A correct internet checksum makes the whole block sum to zero.
        assertEquals(0, IpUdpPacket.checksum(response, 0, 20))
        // UDP checksum (incl. pseudo-header) likewise.
        val pseudo = ByteArray(12)
        reparsed.sourceAddress.copyInto(pseudo, 0)
        reparsed.destAddress.copyInto(pseudo, 4)
        pseudo[9] = 17
        val udpLen = response.size - 20
        pseudo[10] = (udpLen shr 8).toByte(); pseudo[11] = udpLen.toByte()
        var sum = IpUdpPacket.checksum(pseudo, 0, pseudo.size, final = false)
        sum = IpUdpPacket.checksum(response, 20, udpLen, sum, final = true)
        assertEquals(0, sum)
    }

    // --- Audit coverage: fragmentation, IP options, odd lengths. ---

    @Test
    fun fragmentedPacketsAreLeftAlone() {
        val moreFragments = udpPacket()
        moreFragments[6] = 0x20 // MF flag set
        assertNull(IpUdpPacket.parse(moreFragments))
        val offsetFragment = udpPacket()
        offsetFragment[7] = 0x01 // fragment offset != 0
        assertNull(IpUdpPacket.parse(offsetFragment))
    }

    @Test
    fun ipOptionsShiftThePayload() {
        // IHL 6: a 20-byte header plus 4 bytes of options; the UDP
        // header starts at 24 and the payload at 32.
        val payload = byteArrayOf(1, 2, 3)
        val total = 24 + 8 + payload.size
        val out = ByteArray(total)
        out[0] = 0x46
        out[2] = (total shr 8).toByte(); out[3] = total.toByte()
        out[8] = 64; out[9] = 17
        byteArrayOf(10, 0, 0, 5).copyInto(out, 12)
        byteArrayOf(10, 10, 10, 10).copyInto(out, 16)
        out[24] = 0xCF.toByte(); out[25] = 0x37 // source port 53079
        out[27] = 53 // dest port
        val udpLen = 8 + payload.size
        out[28] = (udpLen shr 8).toByte(); out[29] = udpLen.toByte()
        payload.copyInto(out, 32)

        val parsed = IpUdpPacket.parse(out)
        assertNotNull(parsed)
        parsed!!
        assertEquals(32, parsed.payloadOffset)
        assertEquals(3, parsed.payloadLength)
        assertEquals(53, parsed.destPort)
    }

    @Test
    fun oddLengthResponseChecksumsValidate() {
        val request = IpUdpPacket.parse(udpPacket(payload = byteArrayOf(1, 2, 3, 4, 5)))!!
        val response = IpUdpPacket.buildResponse(request, byteArrayOf(9, 9, 9))
        val reparsed = IpUdpPacket.parse(response)!!
        assertEquals(0, IpUdpPacket.checksum(response, 0, 20))
        val pseudo = ByteArray(12)
        reparsed.sourceAddress.copyInto(pseudo, 0)
        reparsed.destAddress.copyInto(pseudo, 4)
        pseudo[9] = 17
        val udpLen = response.size - 20
        pseudo[10] = (udpLen shr 8).toByte(); pseudo[11] = udpLen.toByte()
        var sum = IpUdpPacket.checksum(pseudo, 0, pseudo.size, final = false)
        sum = IpUdpPacket.checksum(response, 20, udpLen, sum, final = true)
        assertEquals(0, sum)
    }
}
