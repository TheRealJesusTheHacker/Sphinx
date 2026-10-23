package com.sentinelsafeguard.sphinx.lists

import java.io.File
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertTrue
import org.junit.Assume.assumeTrue
import org.junit.Test

/**
 * The list updater's per-source failure notes must tell the truth:
 * "kept the previous copy" only when a previous copy is actually
 * saved. A source that has never downloaded successfully has
 * nothing to keep, and claiming otherwise reports protection the
 * phone does not have.
 *
 * The note decision itself is a pure function and is tested
 * directly; the wiring (updateAll passing the store's real
 * saved-file state into it) is pinned by a source assertion, the
 * same pattern FilterTileLogicTest uses for the tile shell —
 * ListUpdater itself drives Android storage and the network, so
 * it cannot run on the JVM.
 */
class ListUpdaterNoteTest {

    @Test
    fun failureNoteClaimsKeptCopyOnlyWhenOneIsSaved() {
        assertEquals(
            "download failed — kept the previous copy",
            ListUpdater.failureNote("download failed", hasPreviousCopy = true),
        )
        val noCopy = ListUpdater.failureNote("download failed", hasPreviousCopy = false)
        assertEquals("download failed — no previous copy is saved", noCopy)
        assertFalse(noCopy.contains("kept the previous copy"))
    }

    @Test
    fun updateAllRoutesBothFailureBranchesThroughTheHonestNote() {
        val candidates = listOf(
            File("app/src/main/java/com/sentinelsafeguard/sphinx/lists/ListUpdater.kt"),
            File("src/main/java/com/sentinelsafeguard/sphinx/lists/ListUpdater.kt"),
        )
        val file = candidates.firstOrNull { it.isFile }
        assumeTrue("ListUpdater.kt not present from this working directory", file != null)
        val text = file!!.readText()
        // Both failure branches (download failed, unparseable
        // download) decide the note from the store's saved-file
        // state — never a hard-coded "kept" claim.
        assertTrue(text.contains("failureNote(\"download failed\", store.savedFile(source) != null)"))
        assertTrue(text.contains("store.savedFile(source) != null"))
        assertFalse(text.contains("\"download failed — kept the previous copy\""))
        assertFalse(text.contains("\"download didn't parse as a blocklist — kept the previous copy\""))
    }
}
