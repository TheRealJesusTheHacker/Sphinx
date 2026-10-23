package com.sentinelsafeguard.sphinx.lists

import android.content.Context
import com.sentinelsafeguard.sphinx.core.ProfileSources
import com.sentinelsafeguard.sphinx.core.ServerProfile
import com.sentinelsafeguard.sphinx.core.SphinxMode
import com.sentinelsafeguard.sphinx.core.TunnelParseResult
import com.sentinelsafeguard.sphinx.core.TunnelProfileParser
import com.sentinelsafeguard.sphinx.core.VpnGate
import com.wireguard.crypto.KeyPair
import java.io.File

/**
 * Where VPN (TUNNEL) server profiles live on the phone, and
 * the tunnel's state record — docs/TUNNEL-SPEC.md.
 *
 * Storage discipline is the fleet's, inherited from ListStore:
 *  - app-private storage only (filesDir): profile files hold
 *    private keys, and this is the most protected per-edition
 *    store Android offers Sphinx (TUNNEL-SPEC, "Private keys
 *    in storage"). Keys are never logged, never put in the
 *    query log, never in diagnostics; they leave this store
 *    only inside an export the user explicitly makes.
 *  - atomic writes (temp file + rename): a profile is never
 *    half-written; a crash mid-write keeps the old profile.
 *  - degrade, never destroy: a stored file that no longer
 *    parses is reported by name with its refusal reason and
 *    left exactly where it is; the rest of the store is
 *    untouched.
 *
 * The tunnel state record (mode, profile, intent — no traffic
 * data, per TUNNEL-SPEC's logging honesty) lives in
 * SharedPreferences beside ListStore's filter intent, under
 * its own keys.
 */
class TunnelStore(context: Context) {

    private val appContext = context.applicationContext
    private val profilesDir = File(appContext.filesDir, "tunnel-profiles").apply { mkdirs() }
    private val prefs = appContext.getSharedPreferences(PREFS_NAME, Context.MODE_PRIVATE)

    // --- Profiles -------------------------------------------------------

    /** Every stored profile that parses, in name order. The
     *  picker starts EMPTY: no bundled servers, no samples —
     *  what is here is only what the user added. */
    fun profiles(): List<ServerProfile> = loadAll().first

    /** filename → refusal reason for stored files that no
     *  longer parse. Named, never silently skipped, and the
     *  files themselves are left untouched. */
    fun profileErrors(): Map<String, String> = loadAll().second

    private fun loadAll(): Pair<List<ServerProfile>, Map<String, String>> {
        val valid = ArrayList<ServerProfile>()
        val errors = LinkedHashMap<String, String>()
        val files = profilesDir.listFiles { f -> f.isFile && f.name.endsWith(".conf") }
            ?.sortedBy { it.name } ?: emptyList()
        for (file in files) {
            val text = try {
                file.readText()
            } catch (e: Exception) {
                errors[file.name] = "unreadable"
                continue
            }
            val fallback = file.name.removeSuffix(".conf")
            when (val result = TunnelProfileParser.parse(text, fallbackName = fallback)) {
                is TunnelParseResult.Valid -> valid.add(result.profile)
                is TunnelParseResult.Refused -> errors[file.name] = result.reason
            }
        }
        return valid to errors
    }

    fun profile(name: String): ServerProfile? =
        profiles().firstOrNull { it.name == name.trim() }

    /**
     * Import config text. The name comes from the Sphinx name
     * comment when present, else [fallbackName] (the file name
     * on file import), else the profile is refused — a profile
     * the user cannot name is a profile they cannot pick.
     * Importing a name that already exists replaces that
     * profile atomically; every other profile is untouched.
     * Returns the stored profile, or the refusal reason.
     */
    fun importProfile(text: String, fallbackName: String? = null): TunnelParseResult {
        val parsed = TunnelProfileParser.parse(text, fallbackName)
        if (parsed is TunnelParseResult.Refused) return parsed
        val profile = (parsed as TunnelParseResult.Valid).profile
        val name = profile.name?.trim()?.takeIf { it.isNotEmpty() }
            ?: return TunnelParseResult.Refused("name-required")
        val named = profile.withName(name)
        writeAtomically(fileFor(name), named.exportText().toByteArray(Charsets.UTF_8))
        return TunnelParseResult.Valid(named)
    }

    /** Remove a profile. The live rules and every other
     *  profile are untouched; deleting the profile a tunnel
     *  state record names does not rewrite that record (the
     *  service degrades it to a leftover, per TUNNEL-SPEC). */
    fun deleteProfile(name: String): Boolean {
        val file = fileFor(name.trim())
        val deleted = file.isFile && file.delete()
        if (deleted) recordProfileSource(name.trim(), null)
        return deleted
    }

    // --- Profile sources (Phase 2: where a profile came from) ----

    /** The recorded source of a stored profile — [VpnGate.SOURCE_VPNGATE]
     *  for directory imports, null for the user's own profiles.
     *  A label only: it drives the source line in the picker and
     *  the disclosure riding again at a connect attempt. */
    fun profileSource(name: String): String? =
        ProfileSources.decode(prefs.getString(KEY_PROFILE_SOURCES, null))[name.trim()]

    fun recordProfileSource(name: String, source: String?) {
        val current = ProfileSources.decode(
            prefs.getString(KEY_PROFILE_SOURCES, null)
        ).toMutableMap()
        if (source == null) current.remove(name) else current[name] = source
        prefs.edit()
            .putString(KEY_PROFILE_SOURCES, ProfileSources.encode(current))
            .apply()
    }

    /**
     * Save a VPN Gate directory row as a profile, through this
     * store's ordinary import path (the Phase 1 OpenVPN record
     * path — it displays with the existing OpenVPN note), with
     * its source recorded as [VpnGate.SOURCE_VPNGATE]. The
     * profile's name is the row's public-server label. Returns
     * the import result; a refused import records nothing.
     */
    fun importVpnGateProfile(row: VpnGate.Row): TunnelParseResult {
        val text = VpnGate.importTextFor(row)
            ?: return TunnelParseResult.Refused("unrecognized-format")
        val result = importProfile(text)
        if (result is TunnelParseResult.Valid) {
            val storedName = result.profile.name?.trim()?.takeIf { it.isNotEmpty() }
            if (storedName != null) {
                recordProfileSource(storedName, VpnGate.SOURCE_VPNGATE)
            }
        }
        return result
    }

    /** The profile's config text for a user-explicit export
     *  (share / QR display). This is the ONLY path by which a
     *  private key leaves the store, and it runs only from
     *  the user's export action in the UI. */
    fun exportText(name: String): String? = profile(name)?.exportText()

    /**
     * Create a profile on this device with a freshly generated
     * keypair. The keypair comes from the tunnel library's own
     * crypto (com.wireguard.crypto.KeyPair — its vetted
     * Curve25519 implementation): never hand-rolled, never
     * derived from the profile name, never shared between
     * profiles. The private key is written once, into the new
     * profile's file, and returned nowhere.
     */
    fun createLocalProfile(
        name: String,
        serverPublicKey: String,
        endpoint: String,
        clientAddress: String,
        dnsServers: List<String> = emptyList(),
    ): TunnelParseResult {
        val keyPair = KeyPair()
        val text = TunnelProfileParser.buildLocalConfigText(
            name = name.trim(),
            privateKey = keyPair.privateKey.toBase64(),
            serverPublicKey = serverPublicKey.trim(),
            endpoint = endpoint.trim(),
            clientAddress = clientAddress.trim(),
            dnsServers = dnsServers,
        )
        return importProfile(text)
    }

    private fun fileFor(name: String): File {
        // Profile names are labels with spaces and punctuation;
        // the file name is a sanitized form, and the profile's
        // own name comment inside the file is the real name.
        val safe = name.map { c -> if (c.isLetterOrDigit() || c in "-_") c else '_' }
            .joinToString("")
            .trim('_')
            .take(60)
            .ifEmpty { "profile" }
        return File(profilesDir, "$safe.conf")
    }

    /** Write [bytes] to [target] so the file is never left
     *  torn: temp file, then rename over the target — the
     *  ListStore discipline, restated for this store's files. */
    private fun writeAtomically(target: File, bytes: ByteArray) {
        val dir = target.parentFile ?: profilesDir
        val temp = File(dir, target.name + ".tmp")
        temp.writeBytes(bytes)
        if (temp.renameTo(target)) return
        val swap = File(dir, target.name + ".swap")
        try {
            temp.copyTo(swap, overwrite = true)
            if (!swap.renameTo(target)) swap.delete()
        } finally {
            temp.delete()
        }
    }

    // --- Tunnel exclusions (the TUNNEL picker's own set) -----------------

    /** Apps the user excluded from the tunnel. Excluded apps
     *  bypass the tunnel entirely — real address, and in
     *  TUNNEL+Blocker their DNS is unfiltered too; the picker
     *  states that in plain words where the set is edited.
     *  This set is the tunnel's own: FILTER-mode app rules are
     *  a different store and neither leaks into the other. */
    fun tunnelExcludedPackages(): Set<String> {
        val raw = prefs.getString(KEY_TUNNEL_EXCLUDED, null) ?: return emptySet()
        return raw.lineSequence().map { it.trim() }.filter { it.isNotEmpty() }.toSet()
    }

    fun saveTunnelExcludedPackages(packages: Set<String>) {
        prefs.edit()
            .putString(KEY_TUNNEL_EXCLUDED, packages.sorted().joinToString("\n"))
            .apply()
    }

    // --- Tunnel state record (mode, profile, intent) ----------------------

    data class TunnelState(
        val mode: SphinxMode,
        val profileName: String?,
        val intentOn: Boolean,
        val withBlocker: Boolean,
        val preVpnMode: SphinxMode?,
    )

    fun tunnelState(): TunnelState = TunnelState(
        mode = parseMode(prefs.getString(KEY_STATE_MODE, null)),
        profileName = prefs.getString(KEY_STATE_PROFILE, null),
        intentOn = prefs.getBoolean(KEY_STATE_INTENT, false),
        withBlocker = prefs.getBoolean(KEY_STATE_BLOCKER, false),
        preVpnMode = prefs.getString(KEY_STATE_PRE_VPN, null)?.let { parseMode(it) },
    )

    /**
     * Record a tunnel state transition. Per TUNNEL-SPEC's
     * intent discipline, callers record intent ONLY at
     * successful transitions (the service calls this after the
     * backend is genuinely up); a leftover or unknown record is
     * shown as a leftover and waits for the user.
     */
    fun recordTunnelState(state: TunnelState) {
        prefs.edit()
            .putString(KEY_STATE_MODE, state.mode.name)
            .putString(KEY_STATE_PROFILE, state.profileName)
            .putBoolean(KEY_STATE_INTENT, state.intentOn)
            .putBoolean(KEY_STATE_BLOCKER, state.withBlocker)
            .putString(KEY_STATE_PRE_VPN, state.preVpnMode?.name)
            .apply()
    }

    fun clearTunnelIntent() {
        prefs.edit()
            .putBoolean(KEY_STATE_INTENT, false)
            .putString(KEY_STATE_MODE, SphinxMode.OFF.name)
            .apply()
    }

    private fun parseMode(raw: String?): SphinxMode =
        SphinxMode.values().firstOrNull { it.name == raw } ?: SphinxMode.OFF

    companion object {
        private const val PREFS_NAME = "sphinx_tunnel"
        private const val KEY_TUNNEL_EXCLUDED = "tunnel_excluded_packages"
        private const val KEY_STATE_MODE = "tunnel_state_mode"
        private const val KEY_STATE_PROFILE = "tunnel_state_profile"
        private const val KEY_STATE_INTENT = "tunnel_state_intent"
        private const val KEY_STATE_BLOCKER = "tunnel_state_blocker"
        private const val KEY_STATE_PRE_VPN = "tunnel_state_pre_vpn"
        private const val KEY_PROFILE_SOURCES = "profile_sources"
    }
}
