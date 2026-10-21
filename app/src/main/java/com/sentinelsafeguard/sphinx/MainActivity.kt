package com.sentinelsafeguard.sphinx

import android.app.Activity
import android.content.Intent
import android.net.VpnService
import android.os.Bundle
import android.os.Handler
import android.os.Looper
import android.widget.Button
import android.widget.TextView
import com.sentinelsafeguard.sphinx.vpn.SphinxVpnService

/**
 * Minimal Phase 1 UI: one toggle, a status line, and the blocked/allowed
 * counters from the running service. Plain Android views — no UI toolkit
 * dependencies. Polish is Phase 4.
 */
class MainActivity : Activity() {

    private lateinit var statusText: TextView
    private lateinit var blockedText: TextView
    private lateinit var allowedText: TextView
    private lateinit var toggleButton: Button

    private val handler = Handler(Looper.getMainLooper())
    private val refresh = object : Runnable {
        override fun run() {
            refreshUi()
            handler.postDelayed(this, REFRESH_MS)
        }
    }

    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)
        setContentView(R.layout.activity_main)
        statusText = findViewById(R.id.statusText)
        blockedText = findViewById(R.id.blockedText)
        allowedText = findViewById(R.id.allowedText)
        toggleButton = findViewById(R.id.toggleButton)
        toggleButton.setOnClickListener { onToggle() }
        refreshUi()
    }

    override fun onResume() {
        super.onResume()
        handler.post(refresh)
    }

    override fun onPause() {
        handler.removeCallbacks(refresh)
        super.onPause()
    }

    private fun onToggle() {
        if (SphinxVpnService.isRunning) {
            startService(
                Intent(this, SphinxVpnService::class.java).setAction(SphinxVpnService.ACTION_STOP)
            )
            refreshUi()
            return
        }
        // The one permission Sphinx needs: Android's standard VPN prompt.
        val consent = VpnService.prepare(this)
        if (consent != null) {
            @Suppress("DEPRECATION")
            startActivityForResult(consent, REQUEST_VPN_CONSENT)
        } else {
            startFilter()
        }
    }

    @Deprecated("Phase 1 uses the classic consent flow; polish is Phase 4.")
    override fun onActivityResult(requestCode: Int, resultCode: Int, data: Intent?) {
        super.onActivityResult(requestCode, resultCode, data)
        if (requestCode == REQUEST_VPN_CONSENT && resultCode == RESULT_OK) {
            startFilter()
        }
    }

    private fun startFilter() {
        startService(
            Intent(this, SphinxVpnService::class.java).setAction(SphinxVpnService.ACTION_START)
        )
        refreshUi()
    }

    private fun refreshUi() {
        val running = SphinxVpnService.isRunning
        statusText.text = getString(
            if (running) R.string.status_on else R.string.status_off
        )
        toggleButton.text = getString(
            if (running) R.string.button_stop else R.string.button_start
        )
        blockedText.text = getString(R.string.counter_blocked, SphinxVpnService.blockedCount.get())
        allowedText.text = getString(R.string.counter_allowed, SphinxVpnService.allowedCount.get())
    }

    companion object {
        private const val REQUEST_VPN_CONSENT = 1001
        private const val REFRESH_MS = 500L
    }
}
