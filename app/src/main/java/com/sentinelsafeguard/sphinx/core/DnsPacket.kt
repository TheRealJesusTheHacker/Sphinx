package com.sentinelsafeguard.sphinx.core

/**
 * Minimal DNS message handling for the Sphinx filter: parse the first
 * question of a query, and build a sinkhole response for blocked names.
 *
 * Pure Kotlin — no Android APIs — so every Sphinx edition can implement
 * the same brain (see docs/FILTER-SPEC.md) and this code is JVM-testable.
 *
 * Sinkhole behavior per the spec:
 *  - A queries are answered with 0.0.0.0
 *  - AAAA queries are answered with ::
 *  - Any other type gets a NOERROR response with no answer records
 *  - TTL is 60 seconds; the ID and question section are echoed exactly
 */
class DnsPacket private constructor(
    val id: Int,
    val isResponse: Boolean,
    val opcode: Int,
    val recursionDesired: Boolean,
    /** Decoded question name, lowercased, no trailing dot. Root is "". */
    val questionName: String,
    val questionType: Int,
    val questionClass: Int,
    /** Offset just past the end of the question section. */
    val questionEnd: Int,
    private val raw: ByteArray,
    private val rawLength: Int,
) {
    companion object {
        const val TYPE_A = 1
        const val TYPE_AAAA = 28
        const val CLASS_IN = 1
        const val HEADER_SIZE = 12
        const val SINKHOLE_TTL_SECONDS = 60

        /**
         * Parse the header and first question. Returns null on any
         * malformation — a filter must never crash on hostile input.
         */
        fun parse(data: ByteArray, length: Int = data.size): DnsPacket? {
            if (length < HEADER_SIZE || length > data.size) return null
            val id = u16(data, 0)
            val flags = u16(data, 2)
            val qdCount = u16(data, 4)
            if (qdCount < 1) return null
            val (name, afterName) = readName(data, HEADER_SIZE, length) ?: return null
            if (afterName + 4 > length) return null
            val qType = u16(data, afterName)
            val qClass = u16(data, afterName + 2)
            return DnsPacket(
                id = id,
                isResponse = flags and 0x8000 != 0,
                opcode = (flags shr 11) and 0x0F,
                recursionDesired = flags and 0x0100 != 0,
                questionName = name,
                questionType = qType,
                questionClass = qClass,
                questionEnd = afterName + 4,
                raw = data,
                rawLength = length,
            )
        }

        /**
         * Read a possibly-compressed domain name starting at [start].
         * Returns the decoded name (lowercased, no trailing dot) and the
         * offset just past the name *in the original stream* — for a name
         * ending in a compression pointer, that is just past the pointer.
         */
        internal fun readName(data: ByteArray, start: Int, limit: Int): Pair<String, Int>? {
            val labels = ArrayList<String>()
            var offset = start
            var streamEnd = -1
            var jumps = 0
            while (true) {
                if (offset >= limit) return null
                val len = data[offset].toInt() and 0xFF
                when {
                    len == 0 -> {
                        if (streamEnd < 0) streamEnd = offset + 1
                        return labels.joinToString(".") to streamEnd
                    }
                    len and 0xC0 == 0xC0 -> {
                        if (offset + 1 >= limit) return null
                        val pointer = ((len and 0x3F) shl 8) or (data[offset + 1].toInt() and 0xFF)
                        if (streamEnd < 0) streamEnd = offset + 2
                        if (++jumps > 32) return null // compression loop guard
                        offset = pointer
                    }
                    len and 0xC0 == 0 -> {
                        if (offset + 1 + len > limit) return null
                        val label = String(data, offset + 1, len, Charsets.US_ASCII)
                        labels.add(label.lowercase())
                        offset += 1 + len
                    }
                    else -> return null // 0x40 / 0x80 label types are not valid here
                }
            }
        }

        internal fun u16(data: ByteArray, offset: Int): Int =
            ((data[offset].toInt() and 0xFF) shl 8) or (data[offset + 1].toInt() and 0xFF)

        internal fun putU16(out: ByteArray, offset: Int, value: Int) {
            out[offset] = (value shr 8).toByte()
            out[offset + 1] = value.toByte()
        }

        internal fun putU32(out: ByteArray, offset: Int, value: Int) {
            out[offset] = (value shr 24).toByte()
            out[offset + 1] = (value shr 16).toByte()
            out[offset + 2] = (value shr 8).toByte()
            out[offset + 3] = value.toByte()
        }
    }

    /**
     * Build the sinkhole response for this query, per FILTER-SPEC.md.
     * Only valid for packets where [isResponse] is false.
     */
    fun buildSinkholeResponse(): ByteArray {
        val rdataLength = when (questionType) {
            TYPE_A -> 4
            TYPE_AAAA -> 16
            else -> 0
        }
        val answerLength = if (rdataLength > 0) 12 + rdataLength else 0
        val out = ByteArray(questionEnd + answerLength)

        // Header + question, echoed from the original packet.
        raw.copyInto(out, 0, 0, questionEnd)

        // Flags: QR=1, opcode copied, RD copied, RA=1, RCODE=0 (NOERROR).
        var flags = 0x8000 or 0x0080
        flags = flags or ((opcode and 0x0F) shl 11)
        if (recursionDesired) flags = flags or 0x0100
        putU16(out, 2, flags)

        // Counts: one question; one answer for A/AAAA, none otherwise.
        putU16(out, 4, 1)
        putU16(out, 6, if (rdataLength > 0) 1 else 0)
        putU16(out, 8, 0)
        putU16(out, 10, 0)

        if (rdataLength > 0) {
            var p = questionEnd
            // Name: compression pointer back to the question name at offset 12.
            out[p++] = 0xC0.toByte()
            out[p++] = 0x0C
            putU16(out, p, questionType); p += 2
            putU16(out, p, CLASS_IN); p += 2
            putU32(out, p, SINKHOLE_TTL_SECONDS); p += 4
            putU16(out, p, rdataLength); p += 2
            // RDATA stays all zeros: 0.0.0.0 for A, :: for AAAA.
        }
        return out
    }
}
