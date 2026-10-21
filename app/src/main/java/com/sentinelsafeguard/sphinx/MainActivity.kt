package com.sentinelsafeguard.sphinx

import android.app.Activity
import android.content.Intent
import android.net.VpnService
import android.os.Bundle
import android.os.Handler
import android.os.Looper
import android.widget.Button
import android.widget.EditText
import android.widget.Switch
import android.widget.TextView
import android.widget.Toast
import com.sentinelsafeguard.sphinx.core.Blocklist
import com.sentinelsafeguard.sphinx.core.ListSource
import com.sentinelsafeguard.sphinx.lists.ListStore
import com.sentinelsafeguard.sphinx.lists.ListUpdater
import com.sentinelsafeguard.sphinx.vpn.SphinxVpnService
import java.net.URI
import java.text.NumberFormat
import java.text.SimpleDateFormat
import java.util.Date
import java.util.Locale

/**
 * Sphinx's UI: the Phase 1 toggle and counters, plus Phase 2's list
 * controls — list status and updates, the list-source editor, the
 * allowlist, and the on-device query log. Plain Android views, no UI
 * toolkit dependencies; visual polish is Phase 4.
 *
 * Heavy work (parsing lists, downloading updates) always runs on a
 * background thread; this activity only renders results.
 */
class MainActivity : Activity() {

    private lateinit var statusText: TextView
    private lateinit var blockedText: TextView
    private lateinit var allowedText: TextView
    private lateinit var toggleButton: Button

    private lateinit var listStatusText: TextView
    private lateinit var updateButton: Button
    private lateinit var updateResultText: TextView
    private lateinit var sourcesEdit: EditText
    private lateinit var saveSourcesButton: Button

    private lateinit var allowlistEdit: EditText
    private lateinit var allowlistItemsText: TextView
    private lateinit var addAllowButton: Button
    private lateinit var removeAllowButton: Button

    private lateinit var logToggle: Switch
    private lateinit var logItemsText: TextView
    private lateinit var clearLogButton: Button

    private lateinit var store: ListStore
    private val handler = Handler(Looper.getMainLooper())

    private val refresh = object : Runnable {
        override fun run() {
            refreshUi()
            handler.postDelayed(this, REFRESH_MS)
        }
    }

    private var lastLogSize = -1
    private var lastLogStamp = -1L

    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)
        setContentView(R.layout.activity_main)
        store = ListStore(this)

        statusText = findViewById(R.id.statusText)
        blockedText = findViewById(R.id.blockedText)
        allowedText = findViewById(R.id.allowedText)
        toggleButton = findViewById(R.id.toggleButton)
        toggleButton.setOnClickListener { onToggle() }

        listStatusText = findViewById(R.id.listStatusText)
        updateButton = findViewById(R.id.updateButton)
        updateButton.setOnClickListener { onUpdateLists() }
        updateResultText = findViewById(R.id.updateResultText)
        sourcesEdit = findViewById(R.id.sourcesEdit)
        sourcesEdit.setText(store.sources().joinToString("\n") { it.url })
        saveSourcesButton = findViewById(R.id.saveSourcesButton)
        saveSourcesButton.setOnClickListener { onSaveSources() }

        allowlistEdit = findViewById(R.id.allowlistEdit)
        allowlistItemsText = findViewById(R.id.allowlistItemsText)
        addAllowButton = findViewById(R.id.addAllowButton)
        addAllowButton.setOnClickListener { onAllowlistChange(add = true) }
        removeAllowButton = findViewById(R.id.removeAllowButton)
        removeAllowButton.setOnClickListener { onAllowlistChange(add = false) }

        logToggle = findViewById(R.id.logToggle)
        logToggle.isChecked = store.queryLogEnabled()
        logToggle.setOnCheckedChangeListener { _, checked ->
            store.setQueryLogEnabled(checked)
            notifyServiceReload()
            refreshLogView(force = true)
        }
        logItemsText = findViewById(R.id.logItemsText)
        clearLogButton = findViewById(R.id.clearLogButton)
        clearLogButton.setOnClickListener {
            SphinxVpnService.queryLog.clear()
            refreshLogView(force = true)
        }

        refreshUi()
        refreshAllowlistView()
        refreshListStatus()
    }

    override fun onResume() {
        super.onResume()
        handler.post(refresh)
    }

    override fun onPause() {
        handler.removeCallbacks(refresh)
        super.onPause()
    }

    // --- Filter toggle (Phase 1) --------------------------------------

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

    // --- List updates (Phase 2) ----------------------------------------

    private fun onUpdateLists() {
        updateButton.isEnabled = false
        updateResultText.text = getString(R.string.update_running)
        Thread({
            val result = ListUpdater(store).updateAll(System.currentTimeMillis())
            handler.post {
                updateButton.isEnabled = true
                updateResultText.text = if (result.success) {
                    getString(R.string.update_success, formatCount(result.totalDomains))
                } else {
                    getString(R.string.update_failed)
                }
                if (result.success) {
                    notifyServiceReload()
                    refreshListStatus()
                }
            }
        }, "sphinx-list-update").start()
    }

    private fun onSaveSources() {
        val urls = sourcesEdit.text.toString().lines()
            .map { it.trim() }
            .filter { it.isNotEmpty() }
        val valid = urls.filter { ListSource.isAcceptableUrl(it) }
        if (valid.isEmpty()) {
            toast(getString(R.string.sources_none_valid))
            return
        }
        if (valid.size < urls.size) {
            toast(getString(R.string.sources_some_invalid))
        }
        val sources = valid.map { url ->
            val host = try {
                URI(url).host ?: url
            } catch (e: Exception) {
                url
            }
            val known = ListSource.DEFAULTS.firstOrNull { it.url == url }
            known ?: ListSource(host, url)
        }
        store.saveSources(sources)
        sourcesEdit.setText(sources.joinToString("\n") { it.url })
        toast(getString(R.string.sources_saved))
        refreshListStatus()
    }

    // --- Allowlist (Phase 2) ---------------------------------------------

    private fun onAllowlistChange(add: Boolean) {
        val name = Blocklist.normalize(allowlistEdit.text.toString())
        if (name == null) {
            toast(getString(R.string.allowlist_bad_domain))
            return
        }
        val entries = store.allowlistEntries().toMutableSet()
        if (add) entries.add(name) else entries.remove(name)
        store.saveAllowlist(entries)
        allowlistEdit.text.clear()
        refreshAllowlistView()
        notifyServiceReload()
    }

    private fun refreshAllowlistView() {
        val entries = store.allowlistEntries()
        allowlistItemsText.text = if (entries.isEmpty()) {
            getString(R.string.allowlist_empty)
        } else {
            entries.joinToString("\n")
        }
    }

    // --- Rendering ---------------------------------------------------------

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
        refreshLogView(force = false)
    }

    private fun refreshListStatus() {
        Thread({
            val status = store.status()
            handler.post {
                listStatusText.text = if (status.usingDownloaded) {
                    getString(
                        R.string.list_status_downloaded,
                        formatCount(status.activeDomains),
                        formatDate(status.lastUpdatedMillis),
                    )
                } else {
                    getString(R.string.list_status_bundled, formatCount(status.activeDomains))
                }
            }
        }, "sphinx-list-status").start()
    }

    private fun refreshLogView(force: Boolean) {
        if (!store.queryLogEnabled()) {
            logItemsText.text = getString(R.string.log_off)
            lastLogSize = -1
            return
        }
        val snapshot = SphinxVpnService.queryLog.snapshot()
        val stamp = snapshot.firstOrNull()?.timestampMillis ?: -1L
        if (!force && snapshot.size == lastLogSize && stamp == lastLogStamp) return
        lastLogSize = snapshot.size
        lastLogStamp = stamp
        logItemsText.text = if (snapshot.isEmpty()) {
            getString(R.string.log_empty)
        } else {
            val timeFormat = SimpleDateFormat("HH:mm:ss", Locale.US)
            snapshot.take(LOG_LINES_SHOWN).joinToString("\n") { entry ->
                val mark = if (entry.blocked) "BLOCKED" else "allowed"
                "${timeFormat.format(Date(entry.timestampMillis))}  $mark  ${entry.name}"
            }
        }
    }

    private fun notifyServiceReload() {
        if (!SphinxVpnService.isRunning) return
        startService(
            Intent(this, SphinxVpnService::class.java)
                .setAction(SphinxVpnService.ACTION_RELOAD_LISTS)
        )
    }

    private fun toast(message: String) {
        Toast.makeText(this, message, Toast.LENGTH_SHORT).show()
    }

    private fun formatCount(value: Int): String =
        NumberFormat.getNumberInstance(Locale.US).format(value)

    private fun formatDate(millis: Long): String =
        if (millis <= 0) "—"
        else SimpleDateFormat("MMM d, yyyy", Locale.US).format(Date(millis))

    companion object {
        private const val REQUEST_VPN_CONSENT = 1001
        private const val REFRESH_MS = 500L
        private const val LOG_LINES_SHOWN = 30
    }
}
