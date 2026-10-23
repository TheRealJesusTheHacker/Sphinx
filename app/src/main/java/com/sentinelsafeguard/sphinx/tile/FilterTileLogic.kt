package com.sentinelsafeguard.sphinx.tile

/**
 * The quick-settings tile's decisions, in pure Kotlin with no
 * Android APIs, so they are JVM-tested here and the Android
 * [SphinxTileService] is only the thin shell that acts on them.
 *
 * The tile mirrors the app's one honest state — the same running
 * flag the status line, the toggle button, and the foreground
 * notification all read (`SphinxVpnService.isRunning`) — and it
 * toggles the filter through exactly the paths the app and the
 * notification already use: the service's ACTION_START /
 * ACTION_STOP intents. VPN consent is respected the same way
 * MainActivity and BootReceiver respect it: consent is Android's
 * `VpnService.prepare()` — null means consent is in place; a
 * non-null intent means the user must grant it in person, in the
 * app, so a tap without consent opens the app and starts nothing.
 */
object FilterTileLogic {

    /** The tile's visual state, mirroring Tile.STATE_ACTIVE /
     *  Tile.STATE_INACTIVE in the shell. */
    enum class TileState { ACTIVE, INACTIVE }

    /** Which existing status string the tile shows as its
     *  subtitle: ON is R.string.status_on, OFF is
     *  R.string.status_off — the very strings the app's status
     *  line renders for the same flag, so the tile can never
     *  claim a state the app itself would not claim. VPN_ON is
     *  the TUNNEL addition: R.string.status_tunnel_tile, the
     *  tile's own rendering of the service's tunnel state. */
    enum class StatusText { ON, OFF, VPN_ON }

    /** What one tap does. STOP_TUNNEL is the TUNNEL addition:
     *  it travels through the same ACTION_STOP intent as
     *  STOP_FILTER — the service's ordinary stop path tears
     *  the tunnel down and returns to the pre-VPN mode. */
    enum class TapAction { START_FILTER, STOP_FILTER, OPEN_APP_FOR_CONSENT, STOP_TUNNEL }

    fun tileState(running: Boolean): TileState =
        if (running) TileState.ACTIVE else TileState.INACTIVE

    fun statusText(running: Boolean): StatusText =
        if (running) StatusText.ON else StatusText.OFF

    /**
     * Running → stop, through ACTION_STOP. Off with consent in
     * place → start, through ACTION_START. Off without consent →
     * open the app, where Android's consent prompt belongs; the
     * tile itself starts nothing in that case.
     */
    fun onTap(running: Boolean, consentGranted: Boolean): TapAction = when {
        running -> TapAction.STOP_FILTER
        consentGranted -> TapAction.START_FILTER
        else -> TapAction.OPEN_APP_FOR_CONSENT
    }

    // --- TUNNEL shapes (Phase 1 of VPN mode) --------------------
    // The same logic pattern, extended — not a forked tile: one
    // tile, one state source (the service's flags), the tunnel
    // taking precedence in display because it is the mode that
    // carries the device's traffic.

    fun tileState(running: Boolean, tunnelActive: Boolean): TileState =
        if (running || tunnelActive) TileState.ACTIVE else TileState.INACTIVE

    fun statusText(running: Boolean, tunnelActive: Boolean): StatusText = when {
        tunnelActive -> StatusText.VPN_ON
        running -> StatusText.ON
        else -> StatusText.OFF
    }

    /**
     * Tunnel up → stop it, through ACTION_STOP (the ordinary
     * stop path returns to the pre-VPN mode). Otherwise the
     * filter rules above decide, unchanged.
     */
    fun onTap(running: Boolean, consentGranted: Boolean, tunnelActive: Boolean): TapAction =
        if (tunnelActive) TapAction.STOP_TUNNEL else onTap(running, consentGranted)
}
