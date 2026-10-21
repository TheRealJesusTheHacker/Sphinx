package com.sentinelsafeguard.sphinx.core

import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertNotNull
import org.junit.Assert.assertNull
import org.junit.Assert.assertTrue
import org.junit.Test

class DnsPacketTest {

    /** Hand-built standard query: id=0x1234, RD=1, one question. */
    private fun query(name: String, type: Int, id: Int = 0x1234): ByteArray {
        val labels = name.split('.')
        val out = ArrayList<Byte>()
        fun u16(v: Int) {
            out.add((v shr 8).toByte()); out.add(v.toByte())
        }
        u16(id)
        u16(0x0100) // RD set
        u16(1) // QDCOUNT
        u16(0); u16(0); u16(0)
        for (label in labels) {
            out.add(label.length.toByte())
            label.forEach { out.add(it.code.toByte()) }
        }
        out.add(0)
        u16(type)
        u16(1) // IN
        return out.toByteArray()
    }

    private fun u16(data: ByteArray, offset: Int): Int =
        ((data[offset].toInt() and 0xFF) shl 8) or (data[offset + 1].toInt() and 0xFF)

    @Test
    fun parsesQuestion() {
        val parsed = DnsPacket.parse(query("Ads.Example.COM", DnsPacket.TYPE_A))
        assertNotNull(parsed)
        parsed!!
        assertEquals(0x1234, parsed.id)
        assertFalse(parsed.isResponse)
        assertTrue(parsed.recursionDesired)
        assertEquals("ads.example.com", parsed.questionName) // lowercased
        assertEquals(DnsPacket.TYPE_A, parsed.questionType)
    }

    @Test
    fun sinkholeAnswersAWithZeroAddress() {
        val q = query("ads.example.com", DnsPacket.TYPE_A)
        val resp = DnsPacket.parse(q)!!.buildSinkholeResponse()

        assertEquals(0x1234, u16(resp, 0)) // ID echoed
        assertTrue(u16(resp, 2) and 0x8000 != 0) // QR = response
        assertEquals(0, u16(resp, 2) and 0x000F) // RCODE = NOERROR
        assertEquals(1, u16(resp, 4)) // QDCOUNT
        assertEquals(1, u16(resp, 6)) // ANCOUNT
        // Question section echoed byte-for-byte (header flags change by
        // design — QR is set — so compare from offset 12 onward).
        val questionEnd = DnsPacket.parse(q)!!.questionEnd
        assertTrue(
            q.copyOfRange(12, questionEnd).contentEquals(resp.copyOfRange(12, questionEnd))
        )
        // Answer: pointer to offset 12, type A, class IN, TTL 60, 0.0.0.0.
        var p = questionEnd
        assertEquals(0xC00C, u16(resp, p)); p += 2
        assertEquals(DnsPacket.TYPE_A, u16(resp, p)); p += 2
        assertEquals(1, u16(resp, p)); p += 2
        val ttl = ((resp[p].toInt() and 0xFF) shl 24) or ((resp[p + 1].toInt() and 0xFF) shl 16) or
            ((resp[p + 2].toInt() and 0xFF) shl 8) or (resp[p + 3].toInt() and 0xFF)
        assertEquals(60, ttl); p += 4
        assertEquals(4, u16(resp, p)); p += 2
        assertTrue(resp.copyOfRange(p, p + 4).all { it.toInt() == 0 })
        assertEquals(p + 4, resp.size)
    }

    @Test
    fun sinkholeAnswersAaaaWithZeroAddress() {
        val q = query("tracker.example.net", DnsPacket.TYPE_AAAA)
        val parsed = DnsPacket.parse(q)!!
        val resp = parsed.buildSinkholeResponse()
        assertEquals(1, u16(resp, 6))
        val p = parsed.questionEnd
        assertEquals(DnsPacket.TYPE_AAAA, u16(resp, p + 2))
        assertEquals(16, u16(resp, p + 10))
        assertTrue(resp.copyOfRange(p + 12, p + 28).all { it.toInt() == 0 })
        assertEquals(p + 28, resp.size)
    }

    @Test
    fun sinkholeForOtherTypesHasNoAnswer() {
        val q = query("example.com", 15) // MX
        val resp = DnsPacket.parse(q)!!.buildSinkholeResponse()
        assertEquals(0, u16(resp, 6)) // ANCOUNT 0
        assertEquals(DnsPacket.parse(q)!!.questionEnd, resp.size)
    }

    @Test
    fun rejectsTruncatedPackets() {
        assertNull(DnsPacket.parse(ByteArray(11)))
        val q = query("example.com", DnsPacket.TYPE_A)
        assertNull(DnsPacket.parse(q, 14)) // cut inside the question name
        assertNull(DnsPacket.parse(q.copyOf(12))) // header only, claims a question
    }

    @Test
    fun rejectsZeroQuestions() {
        val headerOnly = ByteArray(12)
        headerOnly[2] = 0x01 // RD
        assertNull(DnsPacket.parse(headerOnly))
    }
}
