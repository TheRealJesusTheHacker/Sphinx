package com.sentinelsafeguard.sphinx.tile

import org.junit.Assert.assertEquals
import org.junit.Test

/**
 * The quick-settings tile's TUNNEL extension: the existing
 * FilterTileLogic, extended with the tunnel state — the tile
 * reflects a live tunnel as active with the VPN subtitle, and
 * a tap on it stops the tunnel through the same ACTION_STOP
 * path the filter uses. Filter behavior without a tunnel is
 * pinned by FilterTileLogicTest and is unchanged.
 */
class FilterTileLogicTunnelTest {

    @Test
    fun tunnelActiveShowsActiveWithVpnSubtitle() {
        assertEquals(
            FilterTileLogic.TileState.ACTIVE,
            FilterTileLogic.tileState(running = false, tunnelActive = true),
        )
        assertEquals(
            FilterTileLogic.StatusText.VPN_ON,
            FilterTileLogic.statusText(running = false, tunnelActive = true),
        )
        // Tunnel takes display precedence over the filter flag.
        assertEquals(
            FilterTileLogic.StatusText.VPN_ON,
            FilterTileLogic.statusText(running = true, tunnelActive = true),
        )
        assertEquals(
            FilterTileLogic.StatusText.ON,
            FilterTileLogic.statusText(running = true, tunnelActive = false),
        )
        assertEquals(
            FilterTileLogic.StatusText.OFF,
            FilterTileLogic.statusText(running = false, tunnelActive = false),
        )
    }

    @Test
    fun tapWhileTunnelActiveStopsTheTunnel() {
        assertEquals(
            FilterTileLogic.TapAction.STOP_TUNNEL,
            FilterTileLogic.onTap(running = false, consentGranted = true, tunnelActive = true),
        )
        assertEquals(
            FilterTileLogic.TapAction.STOP_TUNNEL,
            FilterTileLogic.onTap(running = true, consentGranted = false, tunnelActive = true),
        )
    }

    @Test
    fun tapWithoutTunnelKeepsTheFilterDecisions() {
        assertEquals(
            FilterTileLogic.TapAction.STOP_FILTER,
            FilterTileLogic.onTap(running = true, consentGranted = true, tunnelActive = false),
        )
        assertEquals(
            FilterTileLogic.TapAction.START_FILTER,
            FilterTileLogic.onTap(running = false, consentGranted = true, tunnelActive = false),
        )
        assertEquals(
            FilterTileLogic.TapAction.OPEN_APP_FOR_CONSENT,
            FilterTileLogic.onTap(running = false, consentGranted = false, tunnelActive = false),
        )
    }
}
