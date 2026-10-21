package com.sentinelsafeguard.sphinx.core

import org.junit.Assert.assertFalse
import org.junit.Assert.assertTrue
import org.junit.Test

class FilterListsTest {

    private val filter = FilterLists(
        blocklist = Blocklist(listOf("example.com", "tracker.net")),
        allowlist = Allowlist(listOf("safe.example.com")),
    )

    @Test
    fun blocklistAppliesWhenAllowlistIsSilent() {
        assertTrue(filter.isBlocked("example.com"))
        assertTrue(filter.isBlocked("ads.example.com"))
        assertTrue(filter.isBlocked("anything.tracker.net"))
    }

    @Test
    fun allowlistWinsAtTheSameLevel() {
        val f = FilterLists(
            blocklist = Blocklist(listOf("example.com")),
            allowlist = Allowlist(listOf("example.com")),
        )
        assertFalse(f.isBlocked("example.com"))
    }

    @Test
    fun allowlistWinsBelowABroaderBlocklistEntry() {
        // Blocklist covers all of example.com; the user carved out one
        // branch of it. The carve-out and everything under it is free,
        // the rest stays blocked (FILTER-SPEC rule 5).
        assertFalse(filter.isBlocked("safe.example.com"))
        assertFalse(filter.isBlocked("deep.safe.example.com"))
        assertTrue(filter.isBlocked("other.example.com"))
    }

    @Test
    fun allowlistDoesNotUnblockItsParent() {
        // Allowlisting safe.example.com says nothing about example.com
        // itself or its other children.
        assertTrue(filter.isBlocked("example.com"))
    }

    @Test
    fun allowlistBroaderThanBlocklistEntryUnblocksTheBranch() {
        val f = FilterLists(
            blocklist = Blocklist(listOf("ads.example.com")),
            allowlist = Allowlist(listOf("example.com")),
        )
        assertFalse(f.isBlocked("ads.example.com"))
        assertFalse(f.isBlocked("x.ads.example.com"))
    }

    @Test
    fun emptyAllowlistChangesNothing() {
        val f = FilterLists(
            blocklist = Blocklist(listOf("example.com")),
            allowlist = Allowlist(emptyList()),
        )
        assertTrue(f.isBlocked("example.com"))
        assertFalse(f.isBlocked("unrelated.org"))
    }

    @Test
    fun allowlistCoversIsCaseInsensitive() {
        assertTrue(Allowlist(listOf("Example.COM")).covers("WWW.EXAMPLE.COM"))
    }
}
