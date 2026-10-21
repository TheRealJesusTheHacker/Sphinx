package com.sentinelsafeguard.sphinx.core

import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertTrue
import org.junit.Test

class BlocklistTest {

    private val list = Blocklist(listOf("example.com", "ads.tracker.net"))

    @Test
    fun exactMatchBlocks() {
        assertTrue(list.isBlocked("example.com"))
        assertTrue(list.isBlocked("ads.tracker.net"))
    }

    @Test
    fun subdomainsBlock() {
        assertTrue(list.isBlocked("ads.example.com"))
        assertTrue(list.isBlocked("a.b.ads.example.com"))
        assertTrue(list.isBlocked("cdn.ads.tracker.net"))
    }

    @Test
    fun parentAndSiblingsDoNotBlock() {
        assertFalse(list.isBlocked("tracker.net")) // parent of an entry
        assertFalse(list.isBlocked("other.tracker.net")) // sibling
        assertFalse(list.isBlocked("notexample.com"))
        assertFalse(list.isBlocked("example.com.evil.net")) // entry is only a prefix-label here
        assertFalse(list.isBlocked("unrelated.org"))
    }

    @Test
    fun matchingIsCaseInsensitiveAndDotTolerant() {
        assertTrue(list.isBlocked("ADS.EXAMPLE.COM"))
        assertTrue(list.isBlocked("ads.example.com."))
    }

    @Test
    fun entriesAreNormalized() {
        val messy = Blocklist(listOf("  Example.ORG. ", "*.doubleclick.net", ""))
        assertTrue(messy.isBlocked("www.example.org"))
        assertTrue(messy.isBlocked("anything.doubleclick.net"))
        assertEquals(2, messy.size)
    }

    @Test
    fun fromLinesHandlesCommentsBlanksAndHostsShape() {
        val list = Blocklist.fromLines(
            sequenceOf(
                "# a comment",
                "",
                "ads.example.com",
                "0.0.0.0 tracker.example.net",
                "127.0.0.1 telemetry.example.org # inline note is a separate token",
                "!!!garbage line, not a domain",
            )
        )
        assertTrue(list.isBlocked("ads.example.com"))
        assertTrue(list.isBlocked("tracker.example.net"))
        assertTrue(list.isBlocked("telemetry.example.org"))
        assertEquals(3, list.size)
    }

    @Test
    fun emptyListBlocksNothing() {
        assertFalse(Blocklist(emptyList()).isBlocked("example.com"))
    }

    // --- Phase 2 list-file parsing -------------------------------------

    @Test
    fun fromLinesHandlesIpv6HostsLines() {
        val list = Blocklist.fromLines(
            sequenceOf(
                "::1 ads.example.com",
                "fe80::1%lo0 tracker.example.net",
                "2001:db8::1 telemetry.example.org",
            )
        )
        assertTrue(list.isBlocked("ads.example.com"))
        assertTrue(list.isBlocked("tracker.example.net"))
        assertTrue(list.isBlocked("telemetry.example.org"))
        assertEquals(3, list.size)
    }

    @Test
    fun fromLinesTakesEveryNameOnAHostsLine() {
        val list = Blocklist.fromLines(
            sequenceOf("0.0.0.0 ads.example.com cdn.ads.example.com metrics.example.net")
        )
        assertTrue(list.isBlocked("ads.example.com"))
        assertTrue(list.isBlocked("cdn.ads.example.com"))
        assertTrue(list.isBlocked("metrics.example.net"))
        assertEquals(3, list.size)
    }

    @Test
    fun fromLinesSkipsReservedLocalNames() {
        val list = Blocklist.fromLines(
            sequenceOf(
                "127.0.0.1 localhost",
                "127.0.0.1 localhost.localdomain",
                "255.255.255.255 broadcasthost",
                "::1 ip6-localhost",
                "::1 ip6-loopback",
                "0.0.0.0 ads.example.com",
            )
        )
        assertEquals(1, list.size)
        assertTrue(list.isBlocked("ads.example.com"))
    }

    @Test
    fun fromLinesSkipsSingleLabelsAndIpLiterals() {
        val list = Blocklist.fromLines(
            sequenceOf(
                "com", // one word would block a whole TLD — never honored
                "net",
                "0.0.0.0", // an address by itself is not a domain entry
                "1.2.3.4",
                "0.0.0.0 real.example.com",
            )
        )
        assertEquals(1, list.size)
        assertTrue(list.isBlocked("real.example.com"))
        assertFalse(list.isBlocked("anything.com"))
        assertFalse(list.isBlocked("anything.net"))
    }

    @Test
    fun fromLinesParsesWildcardPlainFormat() {
        // HaGeZi-style wildcard lists: "*.domain" per line.
        val list = Blocklist.fromLines(
            sequenceOf(
                "*.telemetry.example.com",
                "*.ads.example.net",
            )
        )
        assertTrue(list.isBlocked("telemetry.example.com"))
        assertTrue(list.isBlocked("x.telemetry.example.com"))
        assertTrue(list.isBlocked("ads.example.net"))
        assertEquals(2, list.size)
    }

    @Test
    fun fromLinesDeduplicates() {
        val list = Blocklist.fromLines(
            sequenceOf(
                "ads.example.com",
                "ADS.EXAMPLE.COM.",
                "0.0.0.0 ads.example.com",
            )
        )
        assertEquals(1, list.size)
    }
}
