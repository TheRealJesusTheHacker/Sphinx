package com.sentinelsafeguard.sphinx.core

/**
 * Just enough IPv6 + UDP handling for the filter — the mirror of
 * [IpUdpPacket] for the family the base filter did not speak
 * (fix2 hunt finding F1, 2026-10-23). Before fix2, the TUN offered
 * no IPv6 DNS server and this parser did not exist: every IPv6
 * packet parse returned null in the IPv4-only handler and was
 * dropped in silence, on exactly the IPv6-first carrier networks
 * where the phone failure was reported. Now the FILTER-mode
 * interface offers the virtual IPv6 DNS address too, and DNS that
 * arrives over IPv6 transport is questioned, sinkholed, and
 * forwarded under exactly the rules the IPv4 path applies.
 *
 * Pure Kotlin — no Android APIs. Extension headers and fragments
 * parse to null and are left alone (the resolver's DNS arrives as
 * plain UDP; anything more exotic is not the filter's to answer).
 */
class Ip6UdpPacket private constructor(
    val sourceAddress: ByteArray,
    val destAddress: ByteArray,
    val sourcePort: Int,
    val destPort: Int,
    val payloadOffset: Int,
    val payloadLength: Int,
) {
    companion object {
        private const val IPV6_HEADER = 40
        private const val NEXT_HEADER_UDP = 17
        private const val UDP_HEADER = 8

        fun parse(data: ByteArray, length: Int = data.size): Ip6UdpPacket? {
            if (length < IPV6_HEADER + UDP_HEADER || length > data.size) return null
            val version = (data[0].toInt() and 0xFF) shr 4
            if (version != 6) return null
            val payloadLength = DnsPacket.u16(data, 4)
            if (payloadLength < UDP_HEADER || IPV6_HEADER + payloadLength > length) return null
            if ((data[6].toInt() and 0xFF) != NEXT_HEADER_UDP) return null

            val udpStart = IPV6_HEADER
            val udpLength = DnsPacket.u16(data, udpStart + 4)
            if (udpLength < UDP_HEADER || udpLength > payloadLength) return null

            return Ip6UdpPacket(
                sourceAddress = data.copyOfRange(8, 24),
                destAddress = data.copyOfRange(24, 40),
                sourcePort = DnsPacket.u16(data, udpStart),
                destPort = DnsPacket.u16(data, udpStart + 2),
                payloadOffset = udpStart + UDP_HEADER,
                payloadLength = udpLength - UDP_HEADER,
            )
        }

        /**
         * Build an IPv6/UDP packet carrying [payload] back to the
         * sender of [original]: addresses and ports swapped, the
         * UDP checksum computed over the IPv6 pseudo-header
         * (mandatory in IPv6 — there is no "no checksum" form).
         */
        fun buildResponse(
            original: Ip6UdpPacket,
            payload: ByteArray,
            payloadLength: Int = payload.size,
        ): ByteArray {
            require(payloadLength in 0..payload.size)
            val udpLength = UDP_HEADER + payloadLength
            val out = ByteArray(IPV6_HEADER + udpLength)

            // IPv6 header: version 6, traffic class / flow label 0,
            // payload length, next header UDP, hop limit 64.
            out[0] = 0x60
            DnsPacket.putU16(out, 4, udpLength)
            out[6] = NEXT_HEADER_UDP.toByte()
            out[7] = 64
            original.destAddress.copyInto(out, 8)
            original.sourceAddress.copyInto(out, 24)

            // UDP header.
            val udpStart = IPV6_HEADER
            DnsPacket.putU16(out, udpStart, original.destPort)
            DnsPacket.putU16(out, udpStart + 2, original.sourcePort)
            DnsPacket.putU16(out, udpStart + 4, udpLength)
            DnsPacket.putU16(out, udpStart + 6, 0) // checksum below

            payload.copyInto(out, udpStart + UDP_HEADER, 0, payloadLength)

            // Pseudo-header: source, destination, UDP length (32
            // bits), three zero bytes, next header.
            val pseudo = ByteArray(40)
            original.destAddress.copyInto(pseudo, 0)
            original.sourceAddress.copyInto(pseudo, 16)
            DnsPacket.putU32(pseudo, 32, udpLength)
            pseudo[39] = NEXT_HEADER_UDP.toByte()
            var sum = IpUdpPacket.checksum(pseudo, 0, pseudo.size, checksumSeed = 0, final = false)
            sum = IpUdpPacket.checksum(out, udpStart, udpLength, sum, final = true)
            if (sum == 0) sum = 0xFFFF // a computed zero is sent as all-ones
            DnsPacket.putU16(out, udpStart + 6, sum)
            return out
        }
    }
}
