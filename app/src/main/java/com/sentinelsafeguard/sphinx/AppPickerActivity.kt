package com.sentinelsafeguard.sphinx

import android.app.Activity
import android.app.AlertDialog
import android.content.Intent
import android.content.pm.ApplicationInfo
import android.content.pm.PackageManager
import android.os.Bundle
import android.os.Handler
import android.os.Looper
import android.text.Editable
import android.text.TextWatcher
import android.view.View
import android.view.ViewGroup
import android.widget.ArrayAdapter
import android.widget.EditText
import android.widget.ListView
import android.widget.TextView
import com.sentinelsafeguard.sphinx.core.AppRuleType
import com.sentinelsafeguard.sphinx.core.AppRules
import com.sentinelsafeguard.sphinx.lists.ListStore
import com.sentinelsafeguard.sphinx.vpn.SphinxVpnService

/**
 * The per-app rules picker (Phase 3): every installed app that can
 * use the network, with the rule Sphinx currently holds for it. Tap
 * an app to set, change, or clear its rule.
 *
 * Rules save the moment they're picked. If the filter is running,
 * the interface is rebuilt once — when this screen is left — through
 * the service's ordinary restart path, so a whole editing session
 * costs one rebuild, not one per tap.
 *
 * The installed-app list is read on this phone, for this screen
 * only. It is never stored by Sphinx beyond the rules themselves
 * (which are package names the user picked), and never transmitted.
 */
class AppPickerActivity : Activity() {

    private data class AppEntry(
        val label: String,
        val packageName: String,
    )

    private lateinit var store: ListStore
    private lateinit var listView: ListView
    private lateinit var searchEdit: EditText

    private val handler = Handler(Looper.getMainLooper())
    private var allApps: List<AppEntry> = emptyList()
    private var visibleApps: List<AppEntry> = emptyList()
    private var rules: AppRules = AppRules()
    private var rulesChanged = false

    private val adapter by lazy {
        object : ArrayAdapter<AppEntry>(this, R.layout.app_picker_row, mutableListOf()) {
            override fun getView(position: Int, convertView: View?, parent: ViewGroup): View {
                val view = convertView ?: layoutInflater.inflate(
                    R.layout.app_picker_row, parent, false,
                )
                val app = getItem(position)!!
                view.findViewById<TextView>(R.id.appLabelText).text = app.label
                view.findViewById<TextView>(R.id.appPackageText).text = app.packageName
                view.findViewById<TextView>(R.id.appRuleText).text = when (
                    rules.ruleFor(app.packageName)
                ) {
                    AppRuleType.BLOCKED -> getString(R.string.picker_rule_blocked_short)
                    AppRuleType.EXCLUDED -> getString(R.string.picker_rule_excluded_short)
                    null -> ""
                }
                return view
            }
        }
    }

    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)
        setContentView(R.layout.activity_app_picker)
        store = ListStore(this)
        rules = store.loadAppRules()

        listView = findViewById(R.id.appList)
        listView.adapter = adapter
        listView.setOnItemClickListener { _, _, position, _ ->
            onAppTapped(visibleApps[position])
        }

        searchEdit = findViewById(R.id.appSearchEdit)
        searchEdit.addTextChangedListener(object : TextWatcher {
            override fun afterTextChanged(s: Editable?) = applyFilter()
            override fun beforeTextChanged(s: CharSequence?, a: Int, b: Int, c: Int) = Unit
            override fun onTextChanged(s: CharSequence?, a: Int, b: Int, c: Int) = Unit
        })

        Thread({ loadApps() }, "sphinx-app-picker-load").start()
    }

    override fun onPause() {
        // One rebuild for the whole editing session, through the
        // same restart a stop + start would have done.
        if (rulesChanged && SphinxVpnService.isRunning) {
            startService(
                Intent(this, SphinxVpnService::class.java)
                    .setAction(SphinxVpnService.ACTION_RESTART)
            )
        }
        rulesChanged = false
        super.onPause()
    }

    /** Installed apps that request network access, minus Sphinx
     *  itself (an app ruling itself is a footgun, not a feature).
     *  Runs on a background thread; labels load here so the list
     *  never stutters. */
    private fun loadApps() {
        val pm = packageManager
        val apps = ArrayList<AppEntry>()
        for (info in pm.getInstalledApplications(PackageManager.GET_META_DATA)) {
            if (info.packageName == packageName) continue
            if (!requestsInternet(pm, info)) continue
            val label = try {
                pm.getApplicationLabel(info).toString()
            } catch (e: Exception) {
                info.packageName
            }
            apps.add(AppEntry(label, info.packageName))
        }
        apps.sortWith(compareBy({ it.label.lowercase() }, { it.packageName }))
        handler.post {
            allApps = apps
            applyFilter()
        }
    }

    private fun requestsInternet(pm: PackageManager, info: ApplicationInfo): Boolean =
        try {
            val requested = pm.getPackageInfo(
                info.packageName, PackageManager.GET_PERMISSIONS,
            ).requestedPermissions
            requested?.contains(android.Manifest.permission.INTERNET) == true
        } catch (e: Exception) {
            false
        }

    private fun applyFilter() {
        val query = searchEdit.text.toString().trim().lowercase()
        visibleApps = if (query.isEmpty()) {
            allApps
        } else {
            allApps.filter {
                it.label.lowercase().contains(query) ||
                    it.packageName.lowercase().contains(query)
            }
        }
        adapter.clear()
        adapter.addAll(visibleApps)
        adapter.notifyDataSetChanged()
    }

    private fun onAppTapped(app: AppEntry) {
        val options = arrayOf(
            getString(R.string.picker_rule_none),
            getString(R.string.picker_rule_block),
            getString(R.string.picker_rule_exclude),
        )
        val current = when (rules.ruleFor(app.packageName)) {
            null -> 0
            AppRuleType.BLOCKED -> 1
            AppRuleType.EXCLUDED -> 2
        }
        AlertDialog.Builder(this)
            .setTitle(app.label)
            .setSingleChoiceItems(options, current) { dialog, which ->
                val type = when (which) {
                    1 -> AppRuleType.BLOCKED
                    2 -> AppRuleType.EXCLUDED
                    else -> null
                }
                if (type != rules.ruleFor(app.packageName)) {
                    rules = rules.withRule(app.packageName, type)
                    store.saveAppRules(rules)
                    rulesChanged = true
                    adapter.notifyDataSetChanged()
                }
                dialog.dismiss()
            }
            .setNegativeButton(android.R.string.cancel, null)
            .show()
    }
}
