package com.sentinelsafeguard.sphinx.core

import java.net.InetAddress

/**
 * Building and reading real DNS queries for the diagnostics
 * probe panel (fix2 hunt, 2026-10-23). Pure Kotlin — no Android
 * APIs — so the probe's wire shapes are JVM-testable byte for
 * byte, exactly like the packets the hunt tests construct.
 *
 * The probe asks the same question the phone's own resolver
 * would ask — a standard RD query carrying an EDNS OPT record
 * advertising a 1232-byte UDP payload (the size modern stub
 * resolvers advertise under DNS flag-day guidance) — so a probe
 * result means something about the real path, not about a toy
 * packet no app ever sends.
 */
object DnsProbe {

    /** EDNS UDP payload size the probe advertises, in bytes. */
    const val PROBE_EDNS_UDP_SIZE = 1232

    /**
     * Build a standard recursive query for [name]/[type] with an
     * EDNS OPT additional record (version 0, no flags, no
     * options). [name] must already be normalized (see
     * [Blocklist.normalize]); invalid shapes produce null rather
     * than a malformed packet.
     */
    fun buildQuery(name: String, type: Int, id: Int): ByteArray? {
        if (name.isEmpty()) return null
        val labels = name.split('.')
        for (label in labels) {
            if (label.isEmpty() || label.length > 63) return null
            if (!label.all { it in 'a'..'z' || it in '0'..'9' || it == '-' || it == '_' }) {
                return null
            }
        }
        val out = ArrayList<Byte>()
        fun u16(v: Int) {
            out.add((v shr 8).toByte()); out.add(v.toByte())
        }
        fun u32(v: Int) {
            out.add((v shr 24).toByte()); out.add((v shr 16).toByte())
            out.add((v shr 8).toByte()); out.add(v.toByte())
        }
        u16(id and 0xFFFF)
        u16(0x0100) // RD set — what every stub resolver sends
        u16(1) // QDCOUNT
        u16(0) // ANCOUNT
        u16(0) // NSCOUNT
        u16(1) // ARCOUNT: the OPT record below
        for (label in labels) {
            out.add(label.length.toByte())
            label.forEach { out.add(it.code.toByte()) }
        }
        out.add(0)
        u16(type)
        u16(DnsPacket.CLASS_IN)
        // OPT pseudo-record: root name, type 41, class = the
        // requestor's UDP payload size, TTL = extended-rcode /
        // version / flags (all zero), RDLEN 0 (no options).
        out.add(0)
        u16(41)
        u16(PROBE_EDNS_UDP_SIZE)
        u32(0)
        u16(0)
        return out.toByteArray()
    }

    /** The plain-language shape of one upstream answer. */
    data class AnswerSummary(
        /** NOERROR, NXDOMAIN, SERVFAIL, … as the resolver stated it. */
        val rcodeName: String,
        /** Number of answer records. */
        val answerCount: Int,
        /** First A or AAAA address in the answer section, if any. */
        val firstAddress: String?,
        /** True when the answer carries records but none of them
         *  is an address (a CNAME chain that ends elsewhere, a TXT
         *  answer to an address question, …). */
        val hasNonAddressAnswers: Boolean,
    )

    /**
     * Summarize an answer packet: its RCODE, how many answers it
     * carries, and the first address among them. Walks the answer
     * section with the same compression-aware name reader the
     * filter parses questions with; any malformation produces
     * null rather than a guess.
     */
    fun summarizeAnswer(data: ByteArray, length: Int = data.size): AnswerSummary? {
        if (length < DnsPacket.HEADER_SIZE || length > data.size) return null
        val flags = DnsPacket.u16(data, 2)
        if (flags and 0x8000 == 0) return null // not a response
        val rcode = flags and 0x000F
        val qdCount = DnsPacket.u16(data, 4)
        val anCount = DnsPacket.u16(data, 6)
        var offset = DnsPacket.HEADER_SIZE
        repeat(qdCount) {
            val (_, afterName) = DnsPacket.readName(data, offset, length) ?: return null
            if (afterName + 4 > length) return null
            offset = afterName + 4
        }
        var firstAddress: String? = null
        var sawNonAddress = false
        repeat(anCount) {
            val (_, afterName) = DnsPacket.readName(data, offset, length) ?: return null
            if (afterName + 10 > length) return null
            val type = DnsPacket.u16(data, afterName)
            val rdLength = DnsPacket.u16(data, afterName + 8)
            val rdataStart = afterName + 10
            if (rdataStart + rdLength > length) return null
            when (type) {
                DnsPacket.TYPE_A -> {
                    if (firstAddress == null && rdLength == 4) {
                        firstAddress = InetAddress.getByAddress(
                            data.copyOfRange(rdataStart, rdataStart + 4),
                        ).hostAddress
                    } else if (firstAddress == null) {
                        sawNonAddress = true
                    }
                }
                DnsPacket.TYPE_AAAA -> {
                    if (firstAddress == null && rdLength == 16) {
                        firstAddress = InetAddress.getByAddress(
                            data.copyOfRange(rdataStart, rdataStart + 16),
                        ).hostAddress
                    } else if (firstAddress == null) {
                        sawNonAddress = true
                    }
                }
                else -> sawNonAddress = true
            }
            offset = rdataStart + rdLength
        }
        return AnswerSummary(
            rcodeName = rcodeName(rcode),
            answerCount = anCount,
            firstAddress = firstAddress,
            hasNonAddressAnswers = sawNonAddress && firstAddress == null,
        )
    }

    fun rcodeName(rcode: Int): String = when (rcode) {
        0 -> "NOERROR"
        1 -> "FORMERR"
        2 -> "SERVFAIL"
        3 -> "NXDOMAIN"
        4 -> "NOTIMP"
        5 -> "REFUSED"
        else -> "RCODE $rcode"
    }
}
