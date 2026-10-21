package com.sentinelsafeguard.sphinx.core

/**
 * Just enough IPv4 + UDP handling for the filter: recognize a UDP packet
 * and where its payload lives, and wrap a payload (a DNS response) in a
 * fresh IPv4/UDP packet travelling the other way, with correct checksums.
 *
 * Pure Kotlin — no Android APIs. IPv6 is Phase 3 work; packets that are
 * not plain unfragmented IPv4/UDP parse to null and are left alone.
 */
class IpUdpPacket private constructor(
    val sourceAddress: ByteArray,
    val destAddress: ByteArray,
    val sourcePort: Int,
    val destPort: Int,
    val ipHeaderLength: Int,
    val payloadOffset: Int,
    val payloadLength: Int,
) {
    companion object {
        private const val PROTOCOL_UDP = 17
        private const val IPV4_MIN_HEADER = 20
        private const val UDP_HEADER = 8

        fun parse(data: ByteArray, length: Int = data.size): IpUdpPacket? {
            if (length < IPV4_MIN_HEADER + UDP_HEADER || length > data.size) return null
            val version = (data[0].toInt() and 0xFF) shr 4
            if (version != 4) return null
            val ihl = (data[0].toInt() and 0x0F) * 4
            if (ihl < IPV4_MIN_HEADER) return null
            val totalLength = DnsPacket.u16(data, 2)
            if (totalLength < ihl + UDP_HEADER || totalLength > length) return null
            // Leave fragmented packets alone; DNS traffic is not fragmented
            // in practice and reassembly is out of scope for the filter.
            val flagsAndFragment = DnsPacket.u16(data, 6)
            if (flagsAndFragment and 0x2000 != 0 || flagsAndFragment and 0x1FFF != 0) return null
            if ((data[9].toInt() and 0xFF) != PROTOCOL_UDP) return null

            val udpStart = ihl
            val udpLength = DnsPacket.u16(data, udpStart + 4)
            if (udpLength < UDP_HEADER || udpStart + udpLength > totalLength) return null

            return IpUdpPacket(
                sourceAddress = data.copyOfRange(12, 16),
                destAddress = data.copyOfRange(16, 20),
                sourcePort = DnsPacket.u16(data, udpStart),
                destPort = DnsPacket.u16(data, udpStart + 2),
                ipHeaderLength = ihl,
                payloadOffset = udpStart + UDP_HEADER,
                payloadLength = udpLength - UDP_HEADER,
            )
        }

        /**
         * Build an IPv4/UDP packet carrying [payload] back to the sender of
         * [original]: addresses and ports swapped, checksums computed.
         */
        fun buildResponse(original: IpUdpPacket, payload: ByteArray, payloadLength: Int = payload.size): ByteArray {
            require(payloadLength in 0..payload.size)
            val totalLength = IPV4_MIN_HEADER + UDP_HEADER + payloadLength
            val out = ByteArray(totalLength)

            // IPv4 header
            out[0] = 0x45 // version 4, IHL 5
            out[1] = 0
            DnsPacket.putU16(out, 2, totalLength)
            DnsPacket.putU16(out, 4, 0) // identification
            DnsPacket.putU16(out, 6, 0) // flags + fragment offset
            out[8] = 64 // TTL
            out[9] = PROTOCOL_UDP.toByte()
            original.destAddress.copyInto(out, 12)
            original.sourceAddress.copyInto(out, 16)
            DnsPacket.putU16(out, 10, checksum(out, 0, IPV4_MIN_HEADER))

            // UDP header
            val udpStart = IPV4_MIN_HEADER
            DnsPacket.putU16(out, udpStart, original.destPort)
            DnsPacket.putU16(out, udpStart + 2, original.sourcePort)
            DnsPacket.putU16(out, udpStart + 4, UDP_HEADER + payloadLength)
            DnsPacket.putU16(out, udpStart + 6, 0) // checksum filled below

            payload.copyInto(out, udpStart + UDP_HEADER, 0, payloadLength)

            // UDP checksum covers a pseudo-header (src, dst, protocol, UDP
            // length) plus the UDP segment itself.
            val pseudo = ByteArray(12)
            original.destAddress.copyInto(pseudo, 0)
            original.sourceAddress.copyInto(pseudo, 4)
            pseudo[8] = 0
            pseudo[9] = PROTOCOL_UDP.toByte()
            DnsPacket.putU16(pseudo, 10, UDP_HEADER + payloadLength)
            var udpChecksum = checksum(pseudo, 0, pseudo.size, checksumSeed = 0, final = false)
            udpChecksum = checksum(out, udpStart, UDP_HEADER + payloadLength, udpChecksum, final = true)
            if (udpChecksum == 0) udpChecksum = 0xFFFF // 0 means "no checksum" in UDP
            DnsPacket.putU16(out, udpStart + 6, udpChecksum)
            return out
        }

        /**
         * Internet checksum (RFC 1071). [final] folds carries and
         * complements; pass final=false to chain segments.
         */
        internal fun checksum(
            data: ByteArray,
            offset: Int,
            length: Int,
            checksumSeed: Int = 0,
            final: Boolean = true,
        ): Int {
            var sum = checksumSeed
            var i = offset
            val end = offset + length
            while (i + 1 < end) {
                sum += ((data[i].toInt() and 0xFF) shl 8) or (data[i + 1].toInt() and 0xFF)
                i += 2
            }
            if (i < end) {
                sum += (data[i].toInt() and 0xFF) shl 8
            }
            if (!final) return sum
            while (sum shr 16 != 0) {
                sum = (sum and 0xFFFF) + (sum shr 16)
            }
            return sum.inv() and 0xFFFF
        }
    }
}
