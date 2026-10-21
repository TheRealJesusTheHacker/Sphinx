package com.sentinelsafeguard.sphinx.boot

import android.content.BroadcastReceiver
import android.content.Context
import android.content.Intent
import android.net.VpnService
import com.sentinelsafeguard.sphinx.lists.ListStore
import com.sentinelsafeguard.sphinx.vpn.SphinxVpnService

/**
 * Boot auto-start (Phase 4) — opt-in. When the phone finishes
 * booting, the filter comes back ONLY when all three hold:
 *
 *  1. the user turned "start on boot" on in the app (off by
 *     default — a filter that resurrects itself unasked is a
 *     filter that lies about who is in charge);
 *  2. the filter was ON when the phone shut down — the service
 *     records the user's on/off intent every time it genuinely
 *     starts or stops, and boot honors the intent, so a filter
 *     the user turned off stays off;
 *  3. Android still holds the VPN consent the user granted. If
 *     consent is gone, the receiver does nothing at all: it never
 *     shows UI, never asks for anything — asking is the app's
 *     job, in person.
 *
 * The start goes through the service's ordinary ACTION_START path,
 * so the booted filter runs exactly the lifecycle (and the capture
 * mode, from the stored rules) that a manual start produces.
 */
class BootReceiver : BroadcastReceiver() {

    override fun onReceive(context: Context, intent: Intent) {
        if (intent.action != Intent.ACTION_BOOT_COMPLETED) return
        val store = ListStore(context)
        if (!store.bootAutoStartEnabled()) return
        if (!store.filterOnIntent()) return
        // No consent in place → do nothing. prepare() returns the
        // consent intent when Sphinx is not currently the approved
        // VPN; showing it from a boot receiver is not possible and
        // not wanted.
        if (VpnService.prepare(context) != null) return
        val start = Intent(context, SphinxVpnService::class.java)
            .setAction(SphinxVpnService.ACTION_START)
        try {
            context.startForegroundService(start)
        } catch (e: Exception) {
            // Boot failing must be silent, never a crash dialog at
            // the phone's most visible moment: if the system refuses
            // the start for any reason, Sphinx simply stays off and
            // the user can start it from the app, as if the setting
            // weren't there.
        }
    }
}
