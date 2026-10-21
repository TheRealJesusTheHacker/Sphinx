package com.sentinelsafeguard.sphinx.core

import org.junit.Assert.assertEquals
import org.junit.Assert.assertNull
import org.junit.Assert.assertTrue
import org.junit.Test

class IpFlowTest {

    /** An IPv4 packet: src 192.168.1.5, dst 203.0.113.9, with the
     *  given protocol and transport ports. */
    private fun ipv4Packet(protocol: Int, sourcePort: Int, destPort: Int): ByteArray {
        val packet = ByteArray(20 + 20)
        packet[0] = 0x45 // version 4, IHL 5
        DnsPacket.putU16(packet, 2, packet.size)
        packet[8] = 64
        packet[9] = protocol.toByte()
        byteArrayOf(192.toByte(), 168.toByte(), 1, 5).copyInto(packet, 12)
        byteArrayOf(203.toByte(), 0, 113, 9).copyInto(packet, 16)
        DnsPacket.putU16(packet, 20, sourcePort)
        DnsPacket.putU16(packet, 22, destPort)
        return packet
    }

    @Test
    fun parsesUdpFlow() {
        val flow = IpFlow.parse(ipv4Packet(17, 53000, 53))!!
        assertEquals(4, flow.version)
        assertEquals(IpFlow.PROTOCOL_UDP, flow.protocol)
        assertEquals(53000, flow.sourcePort)
        assertEquals(53, flow.destPort)
        assertTrue(flow.sourceAddress.contentEquals(byteArrayOf(192.toByte(), 168.toByte(), 1, 5)))
        assertTrue(flow.destAddress.contentEquals(byteArrayOf(203.toByte(), 0, 113, 9)))
    }

    @Test
    fun parsesTcpFlow() {
        val flow = IpFlow.parse(ipv4Packet(6, 44000, 443))!!
        assertEquals(IpFlow.PROTOCOL_TCP, flow.protocol)
        assertEquals(44000, flow.sourcePort)
        assertEquals(443, flow.destPort)
    }

    @Test
    fun nonPortProtocolHasNoPorts() {
        val flow = IpFlow.parse(ipv4Packet(1, 0, 0))!! // ICMP
        assertEquals(1, flow.protocol)
        assertEquals(0, flow.sourcePort)
        assertEquals(0, flow.destPort)
    }

    @Test
    fun laterFragmentsHaveNoPorts() {
        val packet = ipv4Packet(6, 44000, 443)
        DnsPacket.putU16(packet, 6, 0x0001) // fragment offset 1: not the first
        val flow = IpFlow.parse(packet)!!
        assertEquals(0, flow.sourcePort)
        assertEquals(0, flow.destPort)
    }

    @Test
    fun parsesIpv6Flow() {
        val packet = ByteArray(40 + 20)
        packet[0] = 0x60 // version 6
        packet[6] = 17 // next header: UDP
        ByteArray(16) { it.toByte() }.copyInto(packet, 8) // source
        ByteArray(16) { (0xA0 + it).toByte() }.copyInto(packet, 24) // dest
        DnsPacket.putU16(packet, 40, 12345)
        DnsPacket.putU16(packet, 42, 853)
        val flow = IpFlow.parse(packet)!!
        assertEquals(6, flow.version)
        assertEquals(IpFlow.PROTOCOL_UDP, flow.protocol)
        assertEquals(12345, flow.sourcePort)
        assertEquals(853, flow.destPort)
        assertEquals(16, flow.sourceAddress.size)
    }

    @Test
    fun truncatedAndForeignPacketsAreRejected() {
        assertNull(IpFlow.parse(ByteArray(0)))
        assertNull(IpFlow.parse(ByteArray(10) { 0x45 }))
        assertNull(IpFlow.parse(ByteArray(60) { 0x50 })) // version 5: not IP we read
        val v6 = ByteArray(20) { 0x60 }
        assertNull(IpFlow.parse(v6)) // IPv6 header needs 40 bytes
    }

    @Test
    fun headerLengthIsHonored() {
        // IHL 6 (one 4-byte option word): ports live 4 bytes later.
        val packet = ByteArray(24 + 20)
        packet[0] = 0x46
        DnsPacket.putU16(packet, 2, packet.size)
        packet[9] = 17
        DnsPacket.putU16(packet, 24, 1111)
        DnsPacket.putU16(packet, 26, 2222)
        val flow = IpFlow.parse(packet)!!
        assertEquals(1111, flow.sourcePort)
        assertEquals(2222, flow.destPort)
    }
}
