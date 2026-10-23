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

/**
 * The smallest possible TCP presence for the filter — a reset,
 * and nothing more (fix2 hunt finding F4, 2026-10-23).
 *
 * The filter answers DNS over UDP. It has no TCP listener and
 * cannot terminate a TCP connection; before fix2, a DNS-over-TCP
 * attempt aimed at the virtual DNS address (a resolver retrying
 * over TCP after a truncated answer, an app whose resolver
 * prefers TCP) met pure silence inside the TUN and waited out
 * its full connect/read timeouts before falling back — seconds
 * of "the network is dead" stamped onto one query. A host with
 * nothing listening on a port answers a SYN with a reset; this
 * class builds exactly that answer, so the asker fails in
 * milliseconds and retries the way it already knows how (UDP,
 * or its next resolver). It is a mitigation, stated as one: it
 * does not give the TUN a TCP DNS service.
 *
 * Pure Kotlin — no Android APIs.
 */
class IpTcpPacket private constructor(
    val sourceAddress: ByteArray,
    val destAddress: ByteArray,
    val sourcePort: Int,
    val destPort: Int,
    val sequence: Int,
    val acknowledgment: Int,
    val flags: Int,
    val payloadLength: Int,
) {
    companion object {
        private const val PROTOCOL_TCP = 6
        private const val IPV4_MIN_HEADER = 20
        private const val TCP_MIN_HEADER = 20

        const val FLAG_FIN = 0x01
        const val FLAG_SYN = 0x02
        const val FLAG_RST = 0x04
        const val FLAG_ACK = 0x10

        fun parse(data: ByteArray, length: Int = data.size): IpTcpPacket? {
            if (length < IPV4_MIN_HEADER + TCP_MIN_HEADER || length > data.size) return null
            val version = (data[0].toInt() and 0xFF) shr 4
            if (version != 4) return null
            val ihl = (data[0].toInt() and 0x0F) * 4
            if (ihl < IPV4_MIN_HEADER) return null
            val totalLength = DnsPacket.u16(data, 2)
            if (totalLength < ihl + TCP_MIN_HEADER || totalLength > length) return null
            if ((data[9].toInt() and 0xFF) != PROTOCOL_TCP) return null
            val tcpStart = ihl
            val dataOffset = ((data[tcpStart + 12].toInt() and 0xFF) shr 4) * 4
            if (dataOffset < TCP_MIN_HEADER || tcpStart + dataOffset > totalLength) return null
            return IpTcpPacket(
                sourceAddress = data.copyOfRange(12, 16),
                destAddress = data.copyOfRange(16, 20),
                sourcePort = DnsPacket.u16(data, tcpStart),
                destPort = DnsPacket.u16(data, tcpStart + 2),
                sequence = u32(data, tcpStart + 4),
                acknowledgment = u32(data, tcpStart + 8),
                flags = data[tcpStart + 13].toInt() and 0xFF,
                payloadLength = totalLength - tcpStart - dataOffset,
            )
        }

        /**
         * The reset a host with no listener sends. Per RFC 9293:
         * if the incoming segment carried ACK, the reset's
         * sequence is that acknowledgment and it carries no ACK
         * of its own; otherwise the reset acknowledges everything
         * the segment carried (SYN and any payload each consume
         * sequence space) and is sent RST+ACK from sequence 0.
         */
        fun buildReset(original: IpTcpPacket): ByteArray {
            val totalLength = IPV4_MIN_HEADER + TCP_MIN_HEADER
            val out = ByteArray(totalLength)

            // IPv4 header (the [IpUdpPacket.buildResponse] shape).
            out[0] = 0x45
            out[1] = 0
            DnsPacket.putU16(out, 2, totalLength)
            DnsPacket.putU16(out, 4, 0)
            DnsPacket.putU16(out, 6, 0)
            out[8] = 64
            out[9] = PROTOCOL_TCP.toByte()
            original.destAddress.copyInto(out, 12)
            original.sourceAddress.copyInto(out, 16)
            DnsPacket.putU16(out, 10, IpUdpPacket.checksum(out, 0, IPV4_MIN_HEADER))

            val tcpStart = IPV4_MIN_HEADER
            DnsPacket.putU16(out, tcpStart, original.destPort)
            DnsPacket.putU16(out, tcpStart + 2, original.sourcePort)
            val hasAck = original.flags and FLAG_ACK != 0
            val seq: Int
            val ack: Int
            val flags: Int
            if (hasAck) {
                seq = original.acknowledgment
                ack = 0
                flags = FLAG_RST
            } else {
                seq = 0
                val consumed = original.payloadLength +
                    (if (original.flags and FLAG_SYN != 0) 1 else 0) +
                    (if (original.flags and FLAG_FIN != 0) 1 else 0)
                ack = original.sequence + consumed
                flags = FLAG_RST or FLAG_ACK
            }
            putU32(out, tcpStart + 4, seq)
            putU32(out, tcpStart + 8, ack)
            out[tcpStart + 12] = (5 shl 4).toByte() // data offset 5 words
            out[tcpStart + 13] = flags.toByte()
            DnsPacket.putU16(out, tcpStart + 14, 0) // window
            DnsPacket.putU16(out, tcpStart + 16, 0) // checksum below
            DnsPacket.putU16(out, tcpStart + 18, 0) // urgent pointer

            // TCP checksum: pseudo-header + segment, as in UDP.
            val pseudo = ByteArray(12)
            original.destAddress.copyInto(pseudo, 0)
            original.sourceAddress.copyInto(pseudo, 4)
            pseudo[8] = 0
            pseudo[9] = PROTOCOL_TCP.toByte()
            DnsPacket.putU16(pseudo, 10, TCP_MIN_HEADER)
            var sum = IpUdpPacket.checksum(pseudo, 0, pseudo.size, checksumSeed = 0, final = false)
            sum = IpUdpPacket.checksum(out, tcpStart, TCP_MIN_HEADER, sum, final = true)
            if (sum == 0) sum = 0xFFFF
            DnsPacket.putU16(out, tcpStart + 16, sum)
            return out
        }

        internal fun u32(data: ByteArray, offset: Int): Int =
            ((data[offset].toInt() and 0xFF) shl 24) or
                ((data[offset + 1].toInt() and 0xFF) shl 16) or
                ((data[offset + 2].toInt() and 0xFF) shl 8) or
                (data[offset + 3].toInt() and 0xFF)

        internal fun putU32(out: ByteArray, offset: Int, value: Int) {
            out[offset] = (value shr 24).toByte()
            out[offset + 1] = (value shr 16).toByte()
            out[offset + 2] = (value shr 8).toByte()
            out[offset + 3] = value.toByte()
        }
    }
}
