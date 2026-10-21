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
import com.sentinelsafeguard.sphinx.core.DropCounts
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
 * Sphinx's UI: the Phase 1 toggle and counters, Phase 2's list
 * controls — list status and updates, the list-source editor, the
 * allowlist, and the on-device query log — and Phase 3's custom block
 * entries and app rules (the summary here; the picker itself is
 * [AppPickerActivity]). Plain Android views, no UI toolkit
 * dependencies; visual polish is Phase 4.
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

    private lateinit var customEdit: EditText
    private lateinit var customItemsText: TextView
    private lateinit var addCustomButton: Button
    private lateinit var removeCustomButton: Button

    private lateinit var rulesSummaryText: TextView
    private lateinit var dropsText: TextView
    private lateinit var chooseAppsButton: Button

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

        customEdit = findViewById(R.id.customEdit)
        customItemsText = findViewById(R.id.customItemsText)
        addCustomButton = findViewById(R.id.addCustomButton)
        addCustomButton.setOnClickListener { onCustomBlockChange(add = true) }
        removeCustomButton = findViewById(R.id.removeCustomButton)
        removeCustomButton.setOnClickListener { onCustomBlockChange(add = false) }

        rulesSummaryText = findViewById(R.id.rulesSummaryText)
        dropsText = findViewById(R.id.dropsText)
        chooseAppsButton = findViewById(R.id.chooseAppsButton)
        chooseAppsButton.setOnClickListener {
            startActivity(Intent(this, AppPickerActivity::class.java))
        }

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
        refreshCustomView()
        refreshRulesView()
        refreshListStatus()
    }

    override fun onResume() {
        super.onResume()
        // The app picker may have changed the rules while we were gone.
        refreshRulesView()
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
        val name = Blocklist.normalizeEntry(allowlistEdit.text.toString())
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

    // --- Custom block entries (Phase 3) ----------------------------------

    private fun onCustomBlockChange(add: Boolean) {
        // Entry validation is the parser's, per the Phase 2 audit
        // rule: normalizeEntry or nothing — an entry the matcher
        // would never honor is refused where it is typed.
        val name = Blocklist.normalizeEntry(customEdit.text.toString())
        if (name == null) {
            toast(getString(R.string.allowlist_bad_domain))
            return
        }
        val entries = store.customBlockEntries().toMutableSet()
        if (add) entries.add(name) else entries.remove(name)
        store.saveCustomBlockEntries(entries)
        customEdit.text.clear()
        refreshCustomView()
        notifyServiceReload()
    }

    private fun refreshCustomView() {
        val entries = store.customBlockEntries()
        customItemsText.text = if (entries.isEmpty()) {
            getString(R.string.custom_empty)
        } else {
            entries.joinToString("\n")
        }
    }

    // --- App rules (Phase 3) -----------------------------------------------

    private fun refreshRulesView() {
        val rules = store.loadAppRules()
        if (rules.isEmpty) {
            rulesSummaryText.text = getString(R.string.rules_none)
            return
        }
        val lines = ArrayList<String>()
        for (pkg in rules.blockedPackages.sorted()) {
            lines.add(getString(R.string.rules_blocked_line, labelFor(pkg)))
        }
        for (pkg in rules.excludedPackages.sorted()) {
            lines.add(getString(R.string.rules_excluded_line, labelFor(pkg)))
        }
        rulesSummaryText.text = lines.joinToString("\n")
    }

    /** Drop counters are in-memory service state; the label cache
     *  keeps the periodic refresh from re-asking the package manager
     *  for the same names every half second. */
    private val labelCache = HashMap<String, String>()

    private fun labelFor(packageName: String): String {
        labelCache[packageName]?.let { return it }
        val label = try {
            val info = packageManager.getApplicationInfo(packageName, 0)
            packageManager.getApplicationLabel(info).toString()
        } catch (e: Exception) {
            packageName
        }
        labelCache[packageName] = label
        return label
    }

    private fun refreshDropsView() {
        val total = SphinxVpnService.droppedPacketCount.get()
        if (total == 0L) {
            dropsText.text = ""
            return
        }
        val lines = ArrayList<String>()
        lines.add(getString(R.string.drops_summary, total))
        val snapshot = SphinxVpnService.dropCounts.snapshot()
        for ((pkg, count) in snapshot.entries.sortedByDescending { it.value }) {
            val who = if (pkg == DropCounts.UNATTRIBUTED) {
                getString(R.string.drops_unknown_app)
            } else {
                labelFor(pkg)
            }
            lines.add(getString(R.string.drops_line, who, count))
        }
        dropsText.text = lines.joinToString("\n")
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
        refreshDropsView()
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
