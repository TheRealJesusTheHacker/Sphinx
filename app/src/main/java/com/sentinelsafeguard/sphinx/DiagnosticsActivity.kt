package com.sentinelsafeguard.sphinx

import android.app.Activity
import android.content.Intent
import android.net.ConnectivityManager
import android.net.NetworkCapabilities
import android.os.Build
import android.os.Bundle
import android.os.Handler
import android.os.Looper
import android.provider.Settings
import android.widget.Button
import android.widget.EditText
import android.widget.TextView
import com.sentinelsafeguard.sphinx.core.UpstreamHealth
import com.sentinelsafeguard.sphinx.vpn.SphinxVpnService
import java.net.InetAddress
import java.text.SimpleDateFormat
import java.util.Date
import java.util.Locale

/**
 * The diagnostics screen (fix2 hunt, required deliverable —
 * 2026-10-23). Plain language only, because its reader is the
 * owner standing in front of a phone where something doesn't
 * work: protection state, the upstream chain IN USE with each
 * resolver's origin and last outcome, the Private DNS mode the
 * system reports, and a one-tap probe panel that classifies a
 * name against the list and then asks the real chain about it.
 *
 * Privacy: this screen shows outcomes and addresses of DNS
 * servers — never traffic content. The only names it displays
 * are ones the user typed into the probe, the two built-in
 * probe names, and what the service's memory-only records
 * already hold.
 */
class DiagnosticsActivity : Activity() {

    private lateinit var buildText: TextView
    private lateinit var protectionText: TextView
    private lateinit var chainText: TextView
    private lateinit var privateDnsText: TextView
    private lateinit var dropsText: TextView
    private lateinit var probeNameEdit: EditText
    private lateinit var probeButton: Button
    private lateinit var probeSiteButton: Button
    private lateinit var probeListedButton: Button
    private lateinit var probeResultText: TextView

    private val handler = Handler(Looper.getMainLooper())
    private var pendingProbeId: Int = -1

    private val refresh = object : Runnable {
        override fun run() {
            refreshAll()
            handler.postDelayed(this, REFRESH_MS)
        }
    }

    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)
        setContentView(R.layout.activity_diagnostics)

        buildText = findViewById(R.id.diagBuildText)
        protectionText = findViewById(R.id.diagProtectionText)
        chainText = findViewById(R.id.diagChainText)
        privateDnsText = findViewById(R.id.diagPrivateDnsText)
        dropsText = findViewById(R.id.diagDropsText)
        probeNameEdit = findViewById(R.id.diagProbeNameEdit)
        probeButton = findViewById(R.id.diagProbeButton)
        probeSiteButton = findViewById(R.id.diagProbeSiteButton)
        probeListedButton = findViewById(R.id.diagProbeListedButton)
        probeResultText = findViewById(R.id.diagProbeResultText)

        probeButton.setOnClickListener {
            startProbe(probeNameEdit.text.toString().trim())
        }
        probeSiteButton.setOnClickListener { startProbe(PROBE_UNLISTED) }
        probeListedButton.setOnClickListener { startProbe(PROBE_LISTED) }

        buildText.text = getString(R.string.build_label)
        refreshAll()
    }

    override fun onResume() {
        super.onResume()
        handler.post(refresh)
    }

    override fun onPause() {
        handler.removeCallbacks(refresh)
        super.onPause()
    }

    private fun startProbe(name: String) {
        if (name.isEmpty()) {
            probeResultText.text = getString(R.string.diag_probe_empty)
            return
        }
        if (!SphinxVpnService.isRunning) {
            probeResultText.text = getString(R.string.diag_probe_needs_filter)
            return
        }
        val id = SphinxVpnService.nextProbeRequestId()
        pendingProbeId = id
        probeResultText.text = getString(R.string.diag_probe_running, name)
        startService(
            Intent(this, SphinxVpnService::class.java)
                .setAction(SphinxVpnService.ACTION_PROBE)
                .putExtra(SphinxVpnService.EXTRA_PROBE_NAME, name)
                .putExtra(SphinxVpnService.EXTRA_PROBE_REQUEST, id),
        )
    }

    private fun refreshAll() {
        protectionText.text = getString(
            if (SphinxVpnService.isRunning) R.string.diag_protection_on
            else R.string.diag_protection_off,
        )
        chainText.text = renderChain()
        privateDnsText.text = renderPrivateDns()
        val drops = SphinxVpnService.queueDropCount.get()
        dropsText.text = if (drops == 0L) {
            getString(R.string.diag_drops_none)
        } else {
            getString(R.string.diag_drops_some, drops)
        }
        val verdict = SphinxVpnService.probeVerdicts[pendingProbeId]
        if (verdict != null) {
            probeResultText.text = verdict.lines.joinToString("\n")
            pendingProbeId = -1
        }
    }

    /** The chain in use, in order, each resolver with where it
     *  came from and what happened the last time it was tried. */
    private fun renderChain(): String {
        val chain = UpstreamHealth.chainInUse
        if (chain.isEmpty()) {
            return getString(R.string.diag_chain_unknown)
        }
        val timeFormat = SimpleDateFormat("HH:mm:ss", Locale.US)
        val lines = ArrayList<String>()
        chain.forEachIndexed { index, entry ->
            val origin = if (entry.fromPhone) {
                getString(R.string.diag_chain_from_phone)
            } else {
                getString(R.string.diag_chain_public)
            }
            lines.add(
                getString(
                    R.string.diag_chain_line, index + 1,
                    displayAddress(entry.address), origin, entry.scopeNote,
                ),
            )
            val record = UpstreamHealth.lastOutcome(entry.address)
            lines.add(
                if (record == null) {
                    getString(R.string.diag_outcome_never)
                } else {
                    val whenText = timeFormat.format(Date(record.atMillis))
                    when (record.outcome) {
                        UpstreamHealth.Outcome.ANSWERED ->
                            getString(R.string.diag_outcome_answered, whenText, record.rttMillis)
                        UpstreamHealth.Outcome.TIMED_OUT_OR_ERROR ->
                            getString(R.string.diag_outcome_timeout, whenText)
                        UpstreamHealth.Outcome.PROTECT_REFUSED ->
                            getString(R.string.diag_outcome_protect, whenText)
                        UpstreamHealth.Outcome.BIND_REFUSED ->
                            getString(R.string.diag_outcome_bind, whenText)
                    }
                },
            )
        }
        if (UpstreamHealth.floorMissing) {
            lines.add(getString(R.string.diag_floor_missing))
        }
        return lines.joinToString("\n")
    }

    /**
     * Android Private DNS as the system reports it (fix2 hunt,
     * F6): read from the default network's link properties —
     * whether Private DNS is active there and which server name
     * it carries — with the global setting as a cross-check on
     * older or vendor builds. Sphinx only reads this; whether
     * Private DNS should be on is the owner's call, and the
     * screen says what each state means for filtering.
     */
    private fun renderPrivateDns(): String {
        var active = false
        var serverName: String? = null
        try {
            val manager = getSystemService(ConnectivityManager::class.java)
            val network = manager?.activeNetwork
            val caps = network?.let { manager.getNetworkCapabilities(it) }
            val isVpn = caps?.hasTransport(NetworkCapabilities.TRANSPORT_VPN) == true
            if (network != null && !isVpn) {
                val props = manager.getLinkProperties(network)
                if (props != null && Build.VERSION.SDK_INT >= Build.VERSION_CODES.P) {
                    active = props.isPrivateDnsActive
                    serverName = props.privateDnsServerName
                }
            }
        } catch (e: Exception) {
            // Fall through to the global setting below.
        }
        val mode = try {
            Settings.Global.getString(contentResolver, "private_dns_mode")
        } catch (e: Exception) {
            null
        }
        return when {
            active && !serverName.isNullOrBlank() ->
                getString(R.string.diag_pdns_on_named, serverName)
            active || mode == "hostname" ->
                getString(R.string.diag_pdns_on)
            mode == "opportunistic" ->
                getString(R.string.diag_pdns_automatic)
            mode == "off" ->
                getString(R.string.diag_pdns_off)
            else ->
                getString(R.string.diag_pdns_automatic)
        }
    }

    private fun displayAddress(address: InetAddress): String {
        val host = address.hostAddress ?: address.toString()
        // A scoped address carries its zone after '%'; say which
        // network it belongs to in words a person can act on.
        return if ('%' in host) {
            host.substringBefore('%') + " (tied to one network interface)"
        } else {
            host
        }
    }

    companion object {
        private const val REFRESH_MS = 500L

        /** Known-unlisted: the owner's own site — it resolved
         *  publicly with the filter off throughout the incident,
         *  and the bundled list carries no entry covering it. */
        private const val PROBE_UNLISTED = "sentinelsafeguard.net"

        /** Known-listed: on the bundled list (the base suite's
         *  BundledListTest pins this name as blocked). */
        private const val PROBE_LISTED = "doubleclick.net"
    }
}
