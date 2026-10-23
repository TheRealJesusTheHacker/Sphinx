package com.sentinelsafeguard.sphinx

import java.io.File
import org.junit.Assert.assertTrue
import org.junit.Assume.assumeTrue
import org.junit.Test

/**
 * Saving the list sources changes which downloaded lists are in
 * force, so it must reload a running filter — the same discipline
 * every other list-affecting edit in MainActivity follows
 * (allowlist, custom entries, the log toggle, a successful list
 * update). Without the reload, the service keeps questioning with
 * a removed source's list while the status line already shows the
 * new source set: the app would claim one thing and do another.
 *
 * MainActivity is an Android Activity and cannot run on the JVM,
 * so the wiring is pinned by a source assertion — the same pattern
 * FilterTileLogicTest uses for the tile shell.
 */
class SourcesSaveReloadTest {

    @Test
    fun savingSourcesReloadsTheRunningFilter() {
        val candidates = listOf(
            File("app/src/main/java/com/sentinelsafeguard/sphinx/MainActivity.kt"),
            File("src/main/java/com/sentinelsafeguard/sphinx/MainActivity.kt"),
        )
        val file = candidates.firstOrNull { it.isFile }
        assumeTrue("MainActivity.kt not present from this working directory", file != null)
        val text = file!!.readText()
        val start = text.indexOf("private fun onSaveSources()")
        assertTrue("onSaveSources not found in MainActivity", start >= 0)
        val body = text.substring(start, text.indexOf("\n    private fun", start))
        assertTrue("onSaveSources must save the sources", body.contains("store.saveSources(sources)"))
        assertTrue(
            "onSaveSources must reload the running filter after saving",
            body.contains("notifyServiceReload()"),
        )
    }
}
