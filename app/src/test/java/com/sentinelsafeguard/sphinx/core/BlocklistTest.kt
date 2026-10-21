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
}
