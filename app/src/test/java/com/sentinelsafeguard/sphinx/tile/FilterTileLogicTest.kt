package com.sentinelsafeguard.sphinx.tile

import java.io.File
import org.junit.Assert.assertEquals
import org.junit.Assert.assertTrue
import org.junit.Assume.assumeTrue
import org.junit.Test

/**
 * The quick-settings tile's decision logic (pure Kotlin) and the
 * manifest declaration that wires it into the system panel.
 * Device-only surfaces — the panel rendering itself, the intent
 * delivery to the running service — are not claimed here; what is
 * pinned is every decision the tile can make and the declaration
 * Android requires for the tile to exist at all.
 */
class FilterTileLogicTest {

    @Test
    fun tileStateMirrorsTheRunningFlag() {
        assertEquals(FilterTileLogic.TileState.ACTIVE, FilterTileLogic.tileState(running = true))
        assertEquals(FilterTileLogic.TileState.INACTIVE, FilterTileLogic.tileState(running = false))
    }

    @Test
    fun statusTextMirrorsTheRunningFlag() {
        // ON maps in the shell to R.string.status_on and OFF to
        // R.string.status_off — the app status line's own strings
        // for the same flag (MainActivity.refreshUi).
        assertEquals(FilterTileLogic.StatusText.ON, FilterTileLogic.statusText(running = true))
        assertEquals(FilterTileLogic.StatusText.OFF, FilterTileLogic.statusText(running = false))
    }

    @Test
    fun tapWhileRunningStops() {
        assertEquals(
            FilterTileLogic.TapAction.STOP_FILTER,
            FilterTileLogic.onTap(running = true, consentGranted = true),
        )
        assertEquals(
            FilterTileLogic.TapAction.STOP_FILTER,
            FilterTileLogic.onTap(running = true, consentGranted = false),
        )
    }

    @Test
    fun tapWhileOffWithConsentStarts() {
        assertEquals(
            FilterTileLogic.TapAction.START_FILTER,
            FilterTileLogic.onTap(running = false, consentGranted = true),
        )
    }

    @Test
    fun tapWhileOffWithoutConsentOpensTheAppAndStartsNothing() {
        assertEquals(
            FilterTileLogic.TapAction.OPEN_APP_FOR_CONSENT,
            FilterTileLogic.onTap(running = false, consentGranted = false),
        )
    }

    @Test
    fun manifestDeclaresTheTileService() {
        val candidates = listOf(
            File("app/src/main/AndroidManifest.xml"),
            File("src/main/AndroidManifest.xml"),
            File("../app/src/main/AndroidManifest.xml"),
        )
        val file = candidates.firstOrNull { it.isFile }
        assumeTrue("AndroidManifest.xml not present from this working directory", file != null)
        val text = file!!.readText()
        val start = text.indexOf(".tile.SphinxTileService")
        assertTrue("tile service not declared in the manifest", start >= 0)
        val block = text.substring(start, text.indexOf("</service>", start))
        assertTrue(block.contains("android.permission.BIND_QUICK_SETTINGS_TILE"))
        assertTrue(block.contains("android.service.quicksettings.action.QS_TILE"))
        assertTrue(block.contains("@string/app_name"))
        assertTrue(block.contains("@drawable/ic_sphinx"))
        assertTrue(block.contains("android.service.quicksettings.TOGGLEABLE_TILE"))
    }

    @Test
    fun tileServiceUsesTheExistingStartStopIntents() {
        val candidates = listOf(
            File("app/src/main/java/com/sentinelsafeguard/sphinx/tile/SphinxTileService.kt"),
            File("src/main/java/com/sentinelsafeguard/sphinx/tile/SphinxTileService.kt"),
        )
        val file = candidates.firstOrNull { it.isFile }
        assumeTrue("SphinxTileService.kt not present from this working directory", file != null)
        val text = file!!.readText()
        // The same intent actions the app and notification use —
        // referenced from the service's own constants, never
        // re-typed as literals that could drift from them.
        assertTrue(text.contains("SphinxVpnService.ACTION_START"))
        assertTrue(text.contains("SphinxVpnService.ACTION_STOP"))
        assertTrue(text.contains("VpnService.prepare"))
        assertTrue(text.contains("R.string.status_on"))
        assertTrue(text.contains("R.string.status_off"))
    }
}
