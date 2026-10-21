package com.sentinelsafeguard.sphinx.core

import java.io.File
import org.junit.Assert.assertTrue
import org.junit.Assume.assumeTrue
import org.junit.Test

/**
 * Loads the real bundled blocklist asset and checks it end to end:
 * it parses to a substantial list, and it blocks the shapes of names
 * a real ad/tracker list exists to block. Runs only when the asset is
 * on disk (it always is in this repo); prints the parse time so the
 * number is on record — see docs/ROADMAP.md, Phase 2 notes.
 */
class BundledListTest {

    private fun assetFile(): File {
        val candidates = listOf(
            File("app/src/main/assets/bundled-blocklist.txt"),
            File("src/main/assets/bundled-blocklist.txt"),
            File("../assets/bundled-blocklist.txt"),
        )
        return candidates.firstOrNull { it.isFile } ?: candidates[0]
    }

    @Test
    fun bundledListParsesSubstantiallyAndFastEnough() {
        val file = assetFile()
        assumeTrue("bundled asset not present", file.isFile)

        val start = System.nanoTime()
        val list = file.bufferedReader().useLines { Blocklist.fromLines(it) }
        val elapsedMs = (System.nanoTime() - start) / 1_000_000
        println("Bundled blocklist: ${list.size} domains parsed in ${elapsedMs} ms")

        assertTrue("expected tens of thousands of domains, got ${list.size}", list.size >= 50_000)
        // Generous ceiling for CI VMs; the point is catching a parser
        // blow-up, not grading hardware. Phones parse this in well
        // under the same bound (see the Phase 2 benchmark note).
        assertTrue("parse took ${elapsedMs} ms", elapsedMs < 10_000)

        // Spot checks against the shape of the real list.
        assertTrue(list.isBlocked("doubleclick.net"))
        assertTrue(list.isBlocked("www.google-analytics.com"))
        assertTrue(list.isBlocked("pixel.facebook.com"))
        assertTrue(!list.isBlocked("example.org"))
        assertTrue(!list.isBlocked("kotlinlang.org"))
    }
}
