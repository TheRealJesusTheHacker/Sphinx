package com.sentinelsafeguard.sphinx.core

/**
 * Just enough IP parsing to say *where a packet was headed* — the
 * protocol and the source/destination addresses and ports — without
 * looking at any payload. The Android app-block mode uses this to
 * attribute dropped packets to the app that sent them (via the
 * platform's connection-owner lookup); nothing here reads, stores,
 * or forwards packet contents.
 *
 * Pure Kotlin — no Android APIs. IPv4 and IPv6 headers are read;
 * fragments and IPv6 extension-header chains are not followed (ports
 * come back 0 for those — attribution is best-effort, the drop never
 * depends on it).
 */
class IpFlow private constructor(
    val version: Int,
    /** IANA protocol number: 6 = TCP, 17 = UDP, anything else as-is. */
    val protocol: Int,
    val sourceAddress: ByteArray,
    val destAddress: ByteArray,
    /** Transport ports, or 0 when the packet carries none that can
     *  be read without reassembly or extension-header walking. */
    val sourcePort: Int,
    val destPort: Int,
) {
    companion object {
        const val PROTOCOL_TCP = 6
        const val PROTOCOL_UDP = 17

        private const val IPV4_MIN_HEADER = 20
        private const val IPV6_HEADER = 40
        private const val TRANSPORT_PORTS = 4

        fun parse(data: ByteArray, length: Int = data.size): IpFlow? {
            if (length < 1 || length > data.size) return null
            return when ((data[0].toInt() and 0xFF) shr 4) {
                4 -> parseV4(data, length)
                6 -> parseV6(data, length)
                else -> null
            }
        }

        private fun parseV4(data: ByteArray, length: Int): IpFlow? {
            if (length < IPV4_MIN_HEADER) return null
            val ihl = (data[0].toInt() and 0x0F) * 4
            if (ihl < IPV4_MIN_HEADER || ihl > length) return null
            // A fragment (beyond the first) carries no transport
            // header at this offset; the first fragment does.
            val flagsAndFragment = DnsPacket.u16(data, 6)
            val fragmentOffset = flagsAndFragment and 0x1FFF
            val protocol = data[9].toInt() and 0xFF
            var sourcePort = 0
            var destPort = 0
            if (fragmentOffset == 0 && isPortProtocol(protocol) &&
                ihl + TRANSPORT_PORTS <= length
            ) {
                sourcePort = DnsPacket.u16(data, ihl)
                destPort = DnsPacket.u16(data, ihl + 2)
            }
            return IpFlow(
                version = 4,
                protocol = protocol,
                sourceAddress = data.copyOfRange(12, 16),
                destAddress = data.copyOfRange(16, 20),
                sourcePort = sourcePort,
                destPort = destPort,
            )
        }

        private fun parseV6(data: ByteArray, length: Int): IpFlow? {
            if (length < IPV6_HEADER) return null
            // Next-header is read at face value: when it names an
            // extension header rather than TCP/UDP, the ports simply
            // stay 0 — the header chain is not walked.
            val protocol = data[6].toInt() and 0xFF
            var sourcePort = 0
            var destPort = 0
            if (isPortProtocol(protocol) && IPV6_HEADER + TRANSPORT_PORTS <= length) {
                sourcePort = DnsPacket.u16(data, IPV6_HEADER)
                destPort = DnsPacket.u16(data, IPV6_HEADER + 2)
            }
            return IpFlow(
                version = 6,
                protocol = protocol,
                sourceAddress = data.copyOfRange(8, 24),
                destAddress = data.copyOfRange(24, 40),
                sourcePort = sourcePort,
                destPort = destPort,
            )
        }

        private fun isPortProtocol(protocol: Int): Boolean =
            protocol == PROTOCOL_TCP || protocol == PROTOCOL_UDP
    }
}
