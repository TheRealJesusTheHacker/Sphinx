package com.sentinelsafeguard.sphinx.core

import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertTrue
import org.junit.Test

/**
 * Phase 3 custom block entries, at the level the store assembles
 * them: entries arrive ONLY through the parser's front door
 * ([Blocklist.parseEntries] / [Blocklist.normalizeEntry] — the Phase 2
 * audit rule), are unioned into the running blocklist as an
 * already-parsed set, and stay subject to allowlist-wins.
 */
class CustomEntriesTest {

    private fun effectiveLists(
        listEntries: Set<String>,
        customLines: List<String>,
        allowlist: Allowlist = Allowlist(emptyList()),
    ): FilterLists {
        val custom = Blocklist.parseEntries(customLines.asSequence())
        val combined = Blocklist(listEntries union custom)
        return FilterLists(combined, allowlist)
    }

    @Test
    fun customEntriesBlockAlongsideListEntries() {
        val lists = effectiveLists(
            listEntries = setOf("from-the-list.example"),
            customLines = listOf("my-custom-block.example"),
        )
        assertTrue(lists.isBlocked("from-the-list.example"))
        assertTrue(lists.isBlocked("my-custom-block.example"))
        assertTrue(lists.isBlocked("ads.my-custom-block.example")) // subdomains too
        assertFalse(lists.isBlocked("something-else.example"))
    }

    @Test
    fun customEntriesStillLoseToTheAllowlist() {
        val lists = effectiveLists(
            listEntries = emptySet(),
            customLines = listOf("tracker.example"),
            allowlist = Allowlist(listOf("tracker.example")),
        )
        assertFalse(lists.isBlocked("tracker.example"))
        assertFalse(lists.isBlocked("cdn.tracker.example"))
    }

    @Test
    fun entriesEnterThroughTheParserRailsOnly() {
        // The same lines a user might type or a file might hold: the
        // rails refuse what load time would have dropped, so nothing
        // silently does nothing.
        val parsed = Blocklist.parseEntries(
            sequenceOf(
                "Good.Example.COM.", // normalizes
                "*.wild.example",
                "singlelabel", // refused: would block a whole TLD
                "localhost", // refused: reserved
                "0.0.0.0 sneaky.example", // hosts shape: the name enters
                "not a domain!!",
            )
        )
        assertEquals(
            setOf("good.example.com", "wild.example", "sneaky.example"),
            parsed,
        )
    }

    @Test
    fun singleEntryValidationMatchesTheParser() {
        assertEquals(
            "typed.example",
            Blocklist.normalizeEntry("  Typed.Example. "),
        )
        assertEquals(null, Blocklist.normalizeEntry("singlelabel"))
        assertEquals(null, Blocklist.normalizeEntry("localhost"))
        assertEquals(null, Blocklist.normalizeEntry("1.2.3.4"))
        assertEquals(null, Blocklist.normalizeEntry(""))
        assertEquals(null, Blocklist.normalizeEntry(null))
    }
}
