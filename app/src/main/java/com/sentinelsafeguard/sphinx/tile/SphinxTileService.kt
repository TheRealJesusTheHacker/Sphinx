package com.sentinelsafeguard.sphinx.tile

import android.app.PendingIntent
import android.content.Intent
import android.graphics.drawable.Icon
import android.net.VpnService
import android.os.Build
import android.os.Handler
import android.os.Looper
import android.service.quicksettings.Tile
import android.service.quicksettings.TileService
import com.sentinelsafeguard.sphinx.MainActivity
import com.sentinelsafeguard.sphinx.R
import com.sentinelsafeguard.sphinx.vpn.SphinxVpnService

/**
 * The quick-settings tile (roadmap R-14): one tap toggles the
 * filter from the system's quick-settings panel, through the
 * very same ACTION_START / ACTION_STOP service intents the app's
 * toggle button and the notification's "Turn off" action use —
 * no second start/stop path exists for it to drift from.
 *
 * Its state is the service's own running flag, rendered with the
 * app's status strings (see [FilterTileLogic]): active with
 * "Sphinx is on — questioning requests" while the filter runs,
 * inactive with "Sphinx is off" while it does not — the tile
 * never claims a state the app would not claim for itself.
 *
 * VPN consent is respected exactly as in MainActivity and
 * BootReceiver: `VpnService.prepare()` returning an intent means
 * consent is not in place, and the tile then opens the app —
 * where the system's consent prompt belongs — and starts
 * nothing. A tile tap is a user interaction, so starting the
 * foreground service for ACTION_START goes through
 * startForegroundService, the same call BootReceiver makes; if
 * the system ever refuses that start, the fallback is the app,
 * never a tile that pretends the filter is on.
 */
class SphinxTileService : TileService() {

    override fun onTileAdded() {
        super.onTileAdded()
        updateTile()
    }

    override fun onStartListening() {
        super.onStartListening()
        updateTile()
    }

    override fun onClick() {
        super.onClick()
        val consentGranted = VpnService.prepare(this) == null
        when (FilterTileLogic.onTap(
            SphinxVpnService.isRunning, consentGranted, SphinxVpnService.tunnelActive,
        )) {
            FilterTileLogic.TapAction.STOP_TUNNEL -> {
                // The ordinary stop path: the service tears the
                // tunnel down and returns to the pre-VPN mode.
                startService(
                    Intent(this, SphinxVpnService::class.java)
                        .setAction(SphinxVpnService.ACTION_STOP)
                )
            }
            FilterTileLogic.TapAction.STOP_FILTER -> {
                startService(
                    Intent(this, SphinxVpnService::class.java)
                        .setAction(SphinxVpnService.ACTION_STOP)
                )
            }
            FilterTileLogic.TapAction.START_FILTER -> {
                try {
                    startForegroundService(
                        Intent(this, SphinxVpnService::class.java)
                            .setAction(SphinxVpnService.ACTION_START)
                    )
                } catch (e: Exception) {
                    // The system refused the start: open the app
                    // instead of leaving a tile that claims a
                    // start nobody made.
                    openApp()
                    return
                }
            }
            FilterTileLogic.TapAction.OPEN_APP_FOR_CONSENT -> {
                openApp()
                return
            }
        }
        // The intent lands on the service asynchronously; refresh
        // once now and once after the service has had the same
        // half-second the app's own UI refresh allows, so the tile
        // settles on the flag the service actually reports.
        updateTile()
        Handler(Looper.getMainLooper()).postDelayed({ updateTile() }, REFRESH_MS)
    }

    private fun openApp() {
        val intent = Intent(this, MainActivity::class.java)
            .addFlags(Intent.FLAG_ACTIVITY_NEW_TASK)
        if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.UPSIDE_DOWN_CAKE) {
            startActivityAndCollapse(
                PendingIntent.getActivity(
                    this, 0, intent,
                    PendingIntent.FLAG_UPDATE_CURRENT or PendingIntent.FLAG_IMMUTABLE,
                )
            )
        } else {
            @Suppress("DEPRECATION")
            startActivityAndCollapse(intent)
        }
    }

    private fun updateTile() {
        val tile = qsTile ?: return
        val running = SphinxVpnService.isRunning
        val tunnelActive = SphinxVpnService.tunnelActive
        tile.state = when (FilterTileLogic.tileState(running, tunnelActive)) {
            FilterTileLogic.TileState.ACTIVE -> Tile.STATE_ACTIVE
            FilterTileLogic.TileState.INACTIVE -> Tile.STATE_INACTIVE
        }
        tile.label = getString(R.string.app_name)
        tile.icon = Icon.createWithResource(this, R.drawable.ic_sphinx)
        val status = getString(
            when (FilterTileLogic.statusText(running, tunnelActive)) {
                FilterTileLogic.StatusText.ON -> R.string.status_on
                FilterTileLogic.StatusText.OFF -> R.string.status_off
                FilterTileLogic.StatusText.VPN_ON -> R.string.status_tunnel_tile
            }
        )
        if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.Q) {
            tile.subtitle = status
        }
        tile.contentDescription = status
        tile.updateTile()
    }

    companion object {
        /** The app UI's own refresh cadence (MainActivity). */
        private const val REFRESH_MS = 500L
    }
}
