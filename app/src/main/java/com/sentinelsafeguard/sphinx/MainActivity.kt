package com.sentinelsafeguard.sphinx

import android.app.Activity
import android.app.AlertDialog
import android.graphics.Bitmap
import android.graphics.BitmapFactory
import android.graphics.Color
import android.content.Intent
import android.content.pm.PackageManager
import android.net.Uri
import android.net.VpnService
import android.os.Build
import android.os.Bundle
import android.os.Handler
import android.os.Looper
import android.os.PowerManager
import android.provider.Settings
import android.view.View
import android.widget.ArrayAdapter
import android.widget.Button
import android.widget.EditText
import android.widget.ImageView
import android.widget.LinearLayout
import android.widget.ScrollView
import android.widget.Spinner
import android.widget.Switch
import android.widget.TextView
import android.widget.Toast
import com.sentinelsafeguard.sphinx.core.Blocklist
import com.sentinelsafeguard.sphinx.core.DropCounts
import com.sentinelsafeguard.sphinx.core.ListSource
import com.sentinelsafeguard.sphinx.core.OvpnProfile
import com.sentinelsafeguard.sphinx.core.SphinxMode
import com.sentinelsafeguard.sphinx.core.TunnelParseResult
import com.sentinelsafeguard.sphinx.core.TunnelProfileParser
import com.sentinelsafeguard.sphinx.core.TunnelQr
import com.sentinelsafeguard.sphinx.core.VpnGate
import com.sentinelsafeguard.sphinx.core.WgProfile
import com.sentinelsafeguard.sphinx.lists.ListStore
import com.sentinelsafeguard.sphinx.lists.TunnelStore
import com.sentinelsafeguard.sphinx.lists.ListUpdater
import com.sentinelsafeguard.sphinx.lists.VpnGateFetcher
import com.sentinelsafeguard.sphinx.lists.VpnGateStore
import com.sentinelsafeguard.sphinx.vpn.SphinxVpnService
import java.net.URI
import java.text.NumberFormat
import java.text.SimpleDateFormat
import java.util.Date
import java.util.Locale

/**
 * Sphinx's UI: the Phase 1 toggle and counters, Phase 2's list
 * controls — list status and updates, the list-source editor, the
 * allowlist, and the on-device query log — Phase 3's custom block
 * entries and app rules (the summary here; the picker itself is
 * [AppPickerActivity]), and Phase 4's profiles, start-on-boot
 * switch, battery section, and the notification-permission flow.
 * Plain Android views, no UI toolkit dependencies.
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

    private lateinit var notificationHintText: TextView

    private lateinit var profilesStatusText: TextView
    private lateinit var profilesSpinner: Spinner
    private lateinit var profileSwitchButton: Button
    private lateinit var profileDeleteButton: Button
    private lateinit var profileNewButton: Button

    private lateinit var bootToggle: Switch

    private lateinit var batteryStatusText: TextView
    private lateinit var batteryButton: Button

    private lateinit var logToggle: Switch
    private lateinit var logItemsText: TextView
    private lateinit var clearLogButton: Button

    private lateinit var tunnelStatusText: TextView
    private lateinit var tunnelProfilesSpinner: Spinner
    private lateinit var tunnelScopeText: TextView
    private lateinit var tunnelPasteEdit: EditText
    private lateinit var tunnelStore: TunnelStore
    private var pendingTunnelBlocker: Boolean = false

    private lateinit var vpnGateStore: VpnGateStore
    private lateinit var vpnGateContainer: LinearLayout
    private lateinit var vpnGateStatusText: TextView
    private lateinit var vpnGateRows: LinearLayout
    private var vpnGateOpened: Boolean = false

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
        tunnelStore = TunnelStore(this)
        vpnGateStore = VpnGateStore(this)

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

        notificationHintText = findViewById(R.id.notificationHintText)

        profilesStatusText = findViewById(R.id.profilesStatusText)
        profilesSpinner = findViewById(R.id.profilesSpinner)
        profileSwitchButton = findViewById(R.id.profileSwitchButton)
        profileSwitchButton.setOnClickListener { onSwitchProfile() }
        profileDeleteButton = findViewById(R.id.profileDeleteButton)
        profileDeleteButton.setOnClickListener { onDeleteProfile() }
        profileNewButton = findViewById(R.id.profileNewButton)
        profileNewButton.setOnClickListener { onNewProfile() }

        bootToggle = findViewById(R.id.bootToggle)
        bootToggle.isChecked = store.bootAutoStartEnabled()
        bootToggle.setOnCheckedChangeListener { _, checked ->
            store.setBootAutoStartEnabled(checked)
        }

        batteryStatusText = findViewById(R.id.batteryStatusText)
        batteryButton = findViewById(R.id.batteryButton)
        batteryButton.setOnClickListener { openBatterySettings() }

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

        findViewById<Button>(R.id.tunnelConnectButton).setOnClickListener {
            onTunnelConnect(withBlocker = false)
        }
        findViewById<Button>(R.id.tunnelConnectBlockerButton).setOnClickListener {
            onTunnelConnect(withBlocker = true)
        }
        findViewById<Button>(R.id.tunnelDisconnectButton).setOnClickListener {
            startService(
                Intent(this, SphinxVpnService::class.java)
                    .setAction(SphinxVpnService.ACTION_STOP)
            )
            refreshUi()
        }
        findViewById<Button>(R.id.tunnelImportPasteButton).setOnClickListener {
            onTunnelImportPaste()
        }
        findViewById<Button>(R.id.tunnelImportFileButton).setOnClickListener {
            @Suppress("DEPRECATION")
            startActivityForResult(
                Intent(Intent.ACTION_OPEN_DOCUMENT).apply {
                    addCategory(Intent.CATEGORY_OPENABLE)
                    type = "*/*"
                },
                REQUEST_TUNNEL_FILE,
            )
        }
        findViewById<Button>(R.id.tunnelImportQrButton).setOnClickListener {
            @Suppress("DEPRECATION")
            startActivityForResult(
                Intent(Intent.ACTION_OPEN_DOCUMENT).apply {
                    addCategory(Intent.CATEGORY_OPENABLE)
                    type = "image/*"
                },
                REQUEST_TUNNEL_QR,
            )
        }
        findViewById<Button>(R.id.tunnelNewButton).setOnClickListener { onTunnelNewProfile() }
        findViewById<Button>(R.id.tunnelExportButton).setOnClickListener { onTunnelExport() }
        findViewById<Button>(R.id.tunnelDeleteButton).setOnClickListener { onTunnelDelete() }
        findViewById<Button>(R.id.tunnelExcludeButton).setOnClickListener { onTunnelExclude() }
        findViewById<Button>(R.id.tunnelAlwaysOnButton).setOnClickListener { openVpnSettings() }
        findViewById<Button>(R.id.tunnelNoticesButton).setOnClickListener { showTunnelNotices() }
        vpnGateContainer = findViewById(R.id.vpnGateContainer)
        vpnGateStatusText = findViewById(R.id.vpnGateStatusText)
        vpnGateRows = findViewById(R.id.vpnGateRows)
        findViewById<Button>(R.id.vpnGateOpenButton).setOnClickListener {
            // The opt-in moment: the section is never pre-enabled.
            // Opening it on purpose is what fetches the feed —
            // at use time, never in the background.
            vpnGateContainer.visibility = View.VISIBLE
            if (!vpnGateOpened) {
                vpnGateOpened = true
                fetchVpnGateDirectory()
            }
        }
        findViewById<Button>(R.id.vpnGateRefreshButton).setOnClickListener {
            fetchVpnGateDirectory()
        }
        tunnelStatusText = findViewById(R.id.tunnelStatusText)
        tunnelProfilesSpinner = findViewById(R.id.tunnelProfilesSpinner)
        tunnelScopeText = findViewById(R.id.tunnelScopeText)
        tunnelPasteEdit = findViewById(R.id.tunnelPasteEdit)
        tunnelProfilesSpinner.onItemSelectedListener =
            object : android.widget.AdapterView.OnItemSelectedListener {
                override fun onItemSelected(
                    parent: android.widget.AdapterView<*>?,
                    view: View?,
                    position: Int,
                    id: Long,
                ) {
                    refreshTunnelScope()
                }

                override fun onNothingSelected(parent: android.widget.AdapterView<*>?) {}
            }
        refreshTunnelView()

        refreshUi()
        refreshAllowlistView()
        refreshCustomView()
        refreshRulesView()
        refreshProfilesView()
        refreshBatteryView()
        refreshNotificationHint()
        refreshListStatus()
    }

    override fun onResume() {
        super.onResume()
        refreshTunnelView()
        // The app picker may have changed the rules while we were gone;
        // the user may also have changed notification or battery
        // settings. Re-read all of it.
        refreshRulesView()
        refreshProfilesView()
        refreshBatteryView()
        refreshNotificationHint()
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
        if (requestCode == REQUEST_VPN_CONSENT_TUNNEL && resultCode == RESULT_OK) {
            startTunnelService(pendingTunnelBlocker)
        }
        if (requestCode == REQUEST_TUNNEL_FILE && resultCode == RESULT_OK) {
            val uri = data?.data
            if (uri != null) {
                Thread({
                    val text = try {
                        contentResolver.openInputStream(uri)?.bufferedReader()
                            ?.use { it.readText() }
                    } catch (e: Exception) {
                        null
                    }
                    val fallback = uri.lastPathSegment
                        ?.substringAfterLast('/')?.substringBeforeLast('.')
                    handler.post {
                        if (text == null) {
                            toast(getString(R.string.vpn_file_failed))
                        } else {
                            importTunnelText(text, fallback)
                        }
                    }
                }, "sphinx-tunnel-file-import").start()
            }
        }
        if (requestCode == REQUEST_TUNNEL_QR && resultCode == RESULT_OK) {
            val uri = data?.data
            if (uri != null) {
                Thread({
                    val decodedText = try {
                        val bitmap = contentResolver.openInputStream(uri)?.use {
                            BitmapFactory.decodeStream(it)
                        }
                        if (bitmap == null) {
                            null
                        } else {
                            val pixels = IntArray(bitmap.width * bitmap.height)
                            bitmap.getPixels(pixels, 0, bitmap.width, 0, 0, bitmap.width, bitmap.height)
                            TunnelQr.decodeArgb(pixels, bitmap.width, bitmap.height)
                        }
                    } catch (e: Exception) {
                        null
                    }
                    handler.post {
                        if (decodedText == null) {
                            toast(getString(R.string.vpn_qr_failed))
                        } else {
                            importTunnelText(decodedText, null)
                        }
                    }
                }, "sphinx-tunnel-qr-import").start()
            }
        }
    }

    private fun startFilter() {
        startService(
            Intent(this, SphinxVpnService::class.java).setAction(SphinxVpnService.ACTION_START)
        )
        maybeAskNotificationPermission()
        refreshUi()
    }

    // --- Notification permission (Phase 4) ------------------------------

    /**
     * The status notification needs the user's say-so on Android 13+.
     * The ask is tied to the moment it becomes relevant — the user
     * has just turned the filter on — and it happens at most once:
     * the asked-marker is set before the prompt shows, so a refusal
     * (or a dismissal) is the user's answer, recorded, and the app
     * explains the consequence in place (refreshNotificationHint)
     * instead of ever asking again.
     */
    private fun maybeAskNotificationPermission() {
        if (Build.VERSION.SDK_INT < Build.VERSION_CODES.TIRAMISU) return
        if (checkSelfPermission(android.Manifest.permission.POST_NOTIFICATIONS) ==
            PackageManager.PERMISSION_GRANTED
        ) {
            return
        }
        if (store.notificationAsked()) return
        store.setNotificationAsked()
        requestPermissions(
            arrayOf(android.Manifest.permission.POST_NOTIFICATIONS),
            REQUEST_NOTIFICATIONS,
        )
    }

    override fun onRequestPermissionsResult(
        requestCode: Int,
        permissions: Array<out String>,
        grantResults: IntArray,
    ) {
        super.onRequestPermissionsResult(requestCode, permissions, grantResults)
        if (requestCode == REQUEST_NOTIFICATIONS) refreshNotificationHint()
    }

    /** When the user has declined, say plainly what that means and
     *  where to change it — a standing note, not a repeated prompt. */
    private fun refreshNotificationHint() {
        val denied = Build.VERSION.SDK_INT >= Build.VERSION_CODES.TIRAMISU &&
            store.notificationAsked() &&
            checkSelfPermission(android.Manifest.permission.POST_NOTIFICATIONS) !=
            PackageManager.PERMISSION_GRANTED
        notificationHintText.visibility = if (denied) View.VISIBLE else View.GONE
        if (denied) notificationHintText.text = getString(R.string.notification_denied)
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

    // --- Profiles (Phase 4) ------------------------------------------------

    private fun refreshProfilesView() {
        val set = store.loadProfileSet()
        profilesStatusText.text = when {
            set.profiles.isEmpty() -> getString(R.string.profiles_empty)
            set.activeName != null -> getString(R.string.profiles_active, set.activeName)
            else -> getString(R.string.profiles_none_active)
        }
        val names = set.profiles.map { it.name }
        val adapter = ArrayAdapter(
            this, android.R.layout.simple_spinner_item, names,
        )
        adapter.setDropDownViewResource(android.R.layout.simple_spinner_dropdown_item)
        profilesSpinner.adapter = adapter
        val activeIndex = names.indexOf(set.activeName)
        if (activeIndex >= 0) profilesSpinner.setSelection(activeIndex)
        val hasProfiles = names.isNotEmpty()
        profilesSpinner.isEnabled = hasProfiles
        profileSwitchButton.isEnabled = hasProfiles
        profileDeleteButton.isEnabled = hasProfiles
    }

    private fun selectedProfileName(): String? = profilesSpinner.selectedItem?.toString()

    private fun onSwitchProfile() {
        val name = selectedProfileName() ?: return
        if (!store.switchProfile(name)) {
            refreshProfilesView()
            return
        }
        toast(getString(R.string.profile_switched))
        // Apply through the audited restart path — the same shutdown/
        // start lifecycle a stop and start would have produced — so
        // the running filter picks up the profile's rules and mode.
        if (SphinxVpnService.isRunning) {
            startService(
                Intent(this, SphinxVpnService::class.java)
                    .setAction(SphinxVpnService.ACTION_RESTART)
            )
        }
        refreshAllowlistView()
        refreshCustomView()
        refreshRulesView()
        refreshProfilesView()
    }

    private fun onDeleteProfile() {
        val name = selectedProfileName() ?: return
        if (store.deleteProfile(name)) {
            toast(getString(R.string.profile_deleted))
        }
        refreshProfilesView()
    }

    private fun onNewProfile() {
        val input = EditText(this)
        input.hint = getString(R.string.profile_name_hint)
        AlertDialog.Builder(this)
            .setTitle(R.string.profile_name_title)
            .setMessage(R.string.profile_name_message)
            .setView(input)
            .setPositiveButton(android.R.string.ok) { _, _ ->
                if (store.createProfile(input.text.toString()) == null) {
                    toast(getString(R.string.profile_bad_name))
                } else {
                    toast(getString(R.string.profile_created))
                    refreshProfilesView()
                }
            }
            .setNegativeButton(android.R.string.cancel, null)
            .show()
    }

    // --- VPN mode / TUNNEL (TUNNEL-SPEC) --------------------------------
    //
    // The server picker starts EMPTY — no bundled servers, no
    // samples. Profiles arrive only by the user's own hand:
    // pasted config text, a picked config file, a QR image of the
    // same config text, or a profile created here with keys
    // generated on this phone. Export is the user's explicit
    // action only, and the export dialog says the private key is
    // inside it.

    private fun selectedTunnelProfileName(): String? =
        tunnelProfilesSpinner.selectedItem?.toString()

    private fun refreshTunnelView() {
        val profiles = tunnelStore.profiles()
        val names = profiles.mapNotNull { it.name }
        val adapter = ArrayAdapter(this, android.R.layout.simple_spinner_item, names)
        adapter.setDropDownViewResource(android.R.layout.simple_spinner_dropdown_item)
        tunnelProfilesSpinner.adapter = adapter
        tunnelProfilesSpinner.isEnabled = names.isNotEmpty()
        refreshTunnelScope()
        refreshTunnelStatusLine()
    }

    private fun refreshTunnelScope() {
        val name = selectedTunnelProfileName()
        val profile = name?.let { tunnelStore.profile(it) }
        val errors = tunnelStore.profileErrors()
        val errorLines = errors.entries.map { (file, reason) ->
            "A stored profile ($file) could not be read: $reason. It was left untouched."
        }
        tunnelScopeText.text = when {
            profile is WgProfile -> {
                val scopeLine = getString(
                    if (profile.scope == "all") R.string.vpn_scope_all else R.string.vpn_scope_some
                )
                val dnsLine = if (profile.dnsServers.isEmpty()) {
                    "DNS: the system resolvers, reached through the tunnel."
                } else {
                    "DNS: ${profile.dnsServers.joinToString(", ")}"
                }
                (listOf(
                    "${profile.name} — ${profile.endpoint ?: "no endpoint"}",
                    scopeLine,
                    dnsLine,
                ) + errorLines).joinToString("\n")
            }
            profile is OvpnProfile -> {
                val lines = ArrayList<String>()
                lines.add(getString(R.string.vpn_openvpn_note))
                if (name != null &&
                    tunnelStore.profileSource(name) == VpnGate.SOURCE_VPNGATE
                ) {
                    lines.add(getString(R.string.vpngate_source_line))
                }
                lines.addAll(errorLines)
                lines.joinToString("\n")
            }
            else ->
                (listOf(getString(R.string.vpn_profiles_empty)) + errorLines).joinToString("\n")
        }
    }

    private fun refreshTunnelStatusLine() {
        if (!::tunnelStatusText.isInitialized) return
        val err = SphinxVpnService.lastTunnelError
        tunnelStatusText.text = when {
            SphinxVpnService.killSwitchBlocked ->
                getString(R.string.vpn_status_kill_switch)
            SphinxVpnService.tunnelActive && SphinxVpnService.tunnelConnectedFresh -> {
                val base = getString(
                    R.string.vpn_status_connected,
                    SphinxVpnService.tunnelProfileName ?: "",
                )
                base + "\n" + getString(
                    if (SphinxVpnService.tunnelWithBlocker) {
                        R.string.vpn_status_blocker_on
                    } else {
                        R.string.vpn_status_unfiltered
                    }
                )
            }
            SphinxVpnService.tunnelActive -> getString(R.string.vpn_status_connecting)
            err != null -> err
            else -> getString(R.string.vpn_status_off)
        }
    }

    private fun importTunnelText(text: String, fallbackName: String?) {
        when (val result = tunnelStore.importProfile(text, fallbackName)) {
            is TunnelParseResult.Valid -> {
                tunnelPasteEdit.text.clear()
                toast(getString(R.string.vpn_imported))
                refreshTunnelView()
            }
            is TunnelParseResult.Refused ->
                toast(getString(R.string.vpn_import_failed, result.reason))
        }
    }

    // --- Public volunteer servers (VPN Gate directory, Phase 2) -----
    //
    // The feed is fetched fresh at use time (HTTPS, size-capped,
    // timeout-bounded — lists/VpnGateFetcher), off the main
    // thread. The last good fetch is cached with its fetch time;
    // a stale cache is shown labeled with its age, never as
    // live; a dead feed with no cache is the honest empty state.
    // Saving a row goes through TunnelStore's ordinary OpenVPN
    // import path with the source recorded (vpngate).

    private fun fetchVpnGateDirectory() {
        vpnGateStatusText.text = getString(R.string.vpngate_fetching)
        vpnGateRows.removeAllViews()
        Thread({
            val cached = vpnGateStore.loadCache()
            val feedText = VpnGateFetcher.fetchFeedText()
            val result = VpnGate.resolveDirectory(feedText, cached)
            if (result is VpnGate.DirectoryResult.Live && feedText != null) {
                vpnGateStore.saveCache(feedText, System.currentTimeMillis())
            }
            handler.post { renderVpnGateDirectory(result) }
        }, "sphinx-vpngate-fetch").start()
    }

    private fun renderVpnGateDirectory(result: VpnGate.DirectoryResult) {
        val rows: List<VpnGate.Row> = when (result) {
            is VpnGate.DirectoryResult.Live -> {
                vpnGateStatusText.text = getString(R.string.vpngate_live_note)
                result.rows
            }
            is VpnGate.DirectoryResult.FromCache -> {
                vpnGateStatusText.text = getString(
                    R.string.vpngate_cache_note,
                    result.cache.ageLabel(System.currentTimeMillis()),
                )
                result.cache.rows
            }
            is VpnGate.DirectoryResult.Empty -> {
                vpnGateStatusText.text = getString(R.string.vpngate_empty_state)
                emptyList()
            }
        }
        vpnGateRows.removeAllViews()
        for (row in rows) {
            val label = TextView(this)
            label.text = row.label
            label.textSize = 15f
            label.setTypeface(label.typeface, android.graphics.Typeface.BOLD)
            vpnGateRows.addView(label)
            val meta = TextView(this)
            meta.text = getString(R.string.vpngate_row_meta, row.score, row.ping)
            meta.textSize = 13f
            vpnGateRows.addView(meta)
            val save = Button(this)
            save.text = getString(R.string.button_vpngate_save)
            save.setOnClickListener {
                when (val imported = tunnelStore.importVpnGateProfile(row)) {
                    is TunnelParseResult.Valid -> {
                        toast(getString(R.string.vpngate_saved))
                        refreshTunnelView()
                    }
                    is TunnelParseResult.Refused ->
                        toast(getString(R.string.vpn_import_failed, imported.reason))
                }
            }
            vpnGateRows.addView(save)
        }
    }

    private fun onTunnelImportPaste() {
        val text = tunnelPasteEdit.text.toString()
        if (text.isBlank()) {
            toast(getString(R.string.vpn_import_failed, "empty"))
            return
        }
        importTunnelText(text, null)
    }

    private fun onTunnelConnect(withBlocker: Boolean) {
        val name = selectedTunnelProfileName()
        if (name == null) {
            toast(getString(R.string.vpn_profiles_empty))
            return
        }
        val profile = tunnelStore.profile(name)
        if (profile is OvpnProfile) {
            // Refused, with the reason named — never a silent
            // failure, never a dead button. For a directory
            // profile the VPN Gate disclosure rides again in
            // front of the refusal (TUNNEL-SPEC, point of use).
            val message = VpnGate.connectAttemptText(
                profile, tunnelStore.profileSource(name)
            ) ?: TunnelProfileParser.OPENVPN_CONNECT_REFUSAL
            AlertDialog.Builder(this)
                .setTitle(name)
                .setMessage(message)
                .setPositiveButton(android.R.string.ok, null)
                .show()
            return
        }
        if (profile !is WgProfile) {
            toast(getString(R.string.vpn_import_failed, "missing profile"))
            return
        }
        // Record WHICH profile/mode is wanted (not intent — the
        // service records intent only when the tunnel is
        // genuinely up), then go through the same VPN consent
        // discipline as the filter: no consent, no start.
        tunnelStore.recordTunnelState(
            TunnelStore.TunnelState(
                mode = SphinxMode.OFF,
                profileName = name,
                intentOn = false,
                withBlocker = withBlocker,
                preVpnMode = if (SphinxVpnService.isRunning) {
                    SphinxMode.FILTER
                } else {
                    SphinxMode.OFF
                },
            )
        )
        pendingTunnelBlocker = withBlocker
        val consent = VpnService.prepare(this)
        if (consent != null) {
            @Suppress("DEPRECATION")
            startActivityForResult(consent, REQUEST_VPN_CONSENT_TUNNEL)
        } else {
            startTunnelService(withBlocker)
        }
    }

    private fun startTunnelService(withBlocker: Boolean) {
        try {
            startForegroundService(
                Intent(this, SphinxVpnService::class.java).setAction(
                    if (withBlocker) {
                        SphinxVpnService.ACTION_START_TUNNEL_BLOCKER
                    } else {
                        SphinxVpnService.ACTION_START_TUNNEL
                    }
                )
            )
        } catch (e: Exception) {
            startService(
                Intent(this, SphinxVpnService::class.java).setAction(
                    if (withBlocker) {
                        SphinxVpnService.ACTION_START_TUNNEL_BLOCKER
                    } else {
                        SphinxVpnService.ACTION_START_TUNNEL
                    }
                )
            )
        }
        maybeAskNotificationPermission()
        refreshUi()
    }

    private fun onTunnelDelete() {
        val name = selectedTunnelProfileName() ?: return
        if (tunnelStore.deleteProfile(name)) {
            toast(getString(R.string.vpn_deleted))
        }
        refreshTunnelView()
    }

    private fun onTunnelNewProfile() {
        val container = LinearLayout(this).apply { orientation = LinearLayout.VERTICAL }
        fun field(hint: String): EditText {
            val edit = EditText(this)
            edit.hint = hint
            edit.textSize = 14f
            container.addView(edit)
            return edit
        }
        val nameEdit = field("Profile name")
        val serverKeyEdit = field("Server public key")
        val endpointEdit = field("Endpoint (host:port)")
        val addressEdit = field("This phone's tunnel address (10.8.0.2/32)")
        val dnsEdit = field("DNS servers (optional)")
        AlertDialog.Builder(this)
            .setTitle(R.string.vpn_new_title)
            .setMessage(R.string.vpn_new_message)
            .setView(container)
            .setPositiveButton(android.R.string.ok) { _, _ ->
                val dns = dnsEdit.text.toString()
                    .split(',').map { it.trim() }.filter { it.isNotEmpty() }
                when (val result = tunnelStore.createLocalProfile(
                    name = nameEdit.text.toString(),
                    serverPublicKey = serverKeyEdit.text.toString(),
                    endpoint = endpointEdit.text.toString(),
                    clientAddress = addressEdit.text.toString(),
                    dnsServers = dns,
                )) {
                    is TunnelParseResult.Valid -> {
                        val profile = result.profile as WgProfile
                        val publicKey = try {
                            com.wireguard.crypto.KeyPair(
                                com.wireguard.crypto.Key.fromBase64(profile.privateKey!!)
                            ).publicKey.toBase64()
                        } catch (e: Exception) {
                            ""
                        }
                        AlertDialog.Builder(this)
                            .setTitle(R.string.vpn_new_title)
                            .setMessage(getString(R.string.vpn_new_created, publicKey))
                            .setPositiveButton(android.R.string.ok, null)
                            .show()
                        refreshTunnelView()
                    }
                    is TunnelParseResult.Refused ->
                        toast(getString(R.string.vpn_import_failed, result.reason))
                }
            }
            .setNegativeButton(android.R.string.cancel, null)
            .show()
    }

    private fun onTunnelExport() {
        // The user's explicit action — the only path by which a
        // private key leaves app-private storage.
        val name = selectedTunnelProfileName() ?: return
        val text = tunnelStore.exportText(name) ?: return
        val container = LinearLayout(this).apply { orientation = LinearLayout.VERTICAL }
        val note = TextView(this)
        note.text = getString(R.string.vpn_export_note)
        container.addView(note)
        val qrMatrix = TunnelQr.encode(text)
        if (qrMatrix != null) {
            val size = qrMatrix.width
            val bitmap = Bitmap.createBitmap(size, size, Bitmap.Config.ARGB_8888)
            for (y in 0 until size) {
                for (x in 0 until size) {
                    bitmap.setPixel(x, y, if (qrMatrix[x, y]) Color.BLACK else Color.WHITE)
                }
            }
            val image = ImageView(this)
            image.setImageBitmap(
                Bitmap.createScaledBitmap(bitmap, 720, 720, false)
            )
            image.adjustViewBounds = true
            container.addView(image)
        }
        val textView = TextView(this)
        textView.text = text
        textView.textSize = 11f
        textView.setTextIsSelectable(true)
        val scroll = ScrollView(this)
        scroll.addView(textView)
        container.addView(scroll)
        AlertDialog.Builder(this)
            .setTitle(getString(R.string.vpn_export_title) + " — " + name)
            .setView(container)
            .setNeutralButton(R.string.button_vpn_share_export) { _, _ ->
                val share = Intent(Intent.ACTION_SEND).apply {
                    type = "text/plain"
                    putExtra(Intent.EXTRA_TEXT, text)
                }
                startActivity(Intent.createChooser(share, name))
            }
            .setPositiveButton(android.R.string.ok, null)
            .show()
    }

    private fun onTunnelExclude() {
        // The tunnel exclusion picker, with the bypass truth
        // stated at the point of choice (TUNNEL-SPEC).
        Thread({
            val apps = try {
                packageManager.getInstalledApplications(0)
                    .map { info -> info.packageName to labelFor(info.packageName) }
                    .sortedBy { it.second.lowercase() }
            } catch (e: Exception) {
                emptyList()
            }
            val excluded = tunnelStore.tunnelExcludedPackages()
            val labels = apps.map { it.second }.toTypedArray()
            val checked = BooleanArray(apps.size) { apps[it].first in excluded }
            handler.post {
                AlertDialog.Builder(this)
                    .setTitle(R.string.button_vpn_exclude)
                    .setMessage(R.string.vpn_exclude_truth)
                    .setMultiChoiceItems(labels, checked) { _, which, isChecked ->
                        checked[which] = isChecked
                    }
                    .setPositiveButton(android.R.string.ok) { _, _ ->
                        val next = apps.filterIndexed { index, _ -> checked[index] }
                            .map { it.first }.toSet()
                        tunnelStore.saveTunnelExcludedPackages(next)
                    }
                    .setNegativeButton(android.R.string.cancel, null)
                    .show()
            }
        }, "sphinx-tunnel-app-list").start()
    }

    /** Android's own VPN settings (always-on VPN, "block
     *  connections without VPN"): offered as the user's choice,
     *  in the system's screen — Sphinx never changes them. */
    private fun openVpnSettings() {
        try {
            startActivity(Intent(Settings.ACTION_VPN_SETTINGS))
        } catch (e: Exception) {
            toast(getString(R.string.vpn_always_on_failed))
        }
    }

    private fun showTunnelNotices() {
        val text = try {
            assets.open("third-party/THIRD-PARTY-NOTICES.txt").bufferedReader()
                .use { it.readText() } +
                "\n\nThe full Apache-2.0 and MIT license texts ship with the app " +
                "in assets/third-party (LICENSE-APACHE-2.0.txt, " +
                "LICENSE-WIREGUARD-GO-MIT.txt)."
        } catch (e: Exception) {
            "Notices file missing from this build."
        }
        val textView = TextView(this)
        textView.text = text
        textView.textSize = 12f
        val scroll = ScrollView(this)
        scroll.addView(textView)
        AlertDialog.Builder(this)
            .setTitle(R.string.vpn_notices_title)
            .setView(scroll)
            .setPositiveButton(android.R.string.ok, null)
            .show()
    }

    // --- Battery (Phase 4) ---------------------------------------------------

    private fun refreshBatteryView() {
        val manager = getSystemService(PowerManager::class.java)
        val exempt = manager.isIgnoringBatteryOptimizations(packageName)
        batteryStatusText.text = getString(
            if (exempt) R.string.battery_exempt else R.string.battery_not_exempt
        )
        batteryButton.visibility = if (exempt) View.GONE else View.VISIBLE
    }

    /**
     * Offer Android's own per-app battery dialog — the user decides,
     * in the system's UI. If a build of Android won't show that
     * dialog, fall back to the battery-optimization settings list.
     * Sphinx itself never changes the setting.
     */
    private fun openBatterySettings() {
        val direct = Intent(Settings.ACTION_REQUEST_IGNORE_BATTERY_OPTIMIZATIONS)
            .setData(Uri.parse("package:$packageName"))
        try {
            startActivity(direct)
        } catch (e: Exception) {
            try {
                startActivity(Intent(Settings.ACTION_IGNORE_BATTERY_OPTIMIZATION_SETTINGS))
            } catch (e2: Exception) {
                toast(getString(R.string.battery_settings_failed))
            }
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
        refreshTunnelStatusLine()
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
        private const val REQUEST_NOTIFICATIONS = 1002
        private const val REQUEST_TUNNEL_FILE = 4101
        private const val REQUEST_TUNNEL_QR = 4102
        private const val REQUEST_VPN_CONSENT_TUNNEL = 4103
        private const val REFRESH_MS = 500L
        private const val LOG_LINES_SHOWN = 30
    }
}
