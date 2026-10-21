package com.sentinelsafeguard.sphinx.lists

import android.content.Context
import com.sentinelsafeguard.sphinx.core.Allowlist
import com.sentinelsafeguard.sphinx.core.AppRules
import com.sentinelsafeguard.sphinx.core.Blocklist
import com.sentinelsafeguard.sphinx.core.FilterLists
import com.sentinelsafeguard.sphinx.core.ListSource
import com.sentinelsafeguard.sphinx.core.ListValidation
import java.io.File
import java.security.MessageDigest

/**
 * Where Sphinx keeps its lists on the phone, and how the working set
 * is chosen. All storage is app-private (filesDir / SharedPreferences)
 * — nothing here is visible to other apps or leaves the device.
 *
 * Which blocklist is active (docs/FILTER-SPEC.md, "List updates"):
 *  - If downloaded lists are on disk and together pass the sanity
 *    gate, they are the blocklist.
 *  - Otherwise the list bundled with the app is the blocklist. The
 *    bundled list is never modified by updates, so there is always a
 *    known-good list to fall back to.
 */
class ListStore(context: Context) {

    private val appContext = context.applicationContext
    private val listsDir = File(appContext.filesDir, "lists").apply { mkdirs() }
    private val allowlistFile = File(appContext.filesDir, "allowlist.txt")
    private val customBlockFile = File(appContext.filesDir, "custom-block.txt")
    private val appRulesFile = File(appContext.filesDir, "app-rules.txt")
    private val prefs = appContext.getSharedPreferences(PREFS_NAME, Context.MODE_PRIVATE)

    // --- Sources --------------------------------------------------------

    fun sources(): List<ListSource> {
        val raw = prefs.getString(KEY_SOURCES, null) ?: return ListSource.DEFAULTS
        val parsed = raw.lineSequence().mapNotNull { line ->
            val tab = line.indexOf('\t')
            if (tab <= 0) return@mapNotNull null
            val source = ListSource(
                line.substring(0, tab),
                line.substring(tab + 1).trim(),
            )
            if (ListSource.isAcceptableUrl(source.url)) source else null
        }.toList()
        return parsed.ifEmpty { ListSource.DEFAULTS }
    }

    fun saveSources(sources: List<ListSource>) {
        prefs.edit()
            .putString(KEY_SOURCES, sources.joinToString("\n") { "${it.name}\t${it.url}" })
            .apply()
        pruneOrphanFiles(sources)
    }

    // --- Downloaded list files ------------------------------------------

    /** The on-disk file holding the downloaded copy of [source]'s list. */
    fun fileFor(source: ListSource): File = File(listsDir, fileNameFor(source.url))

    fun savedFile(source: ListSource): File? = fileFor(source).takeIf { it.isFile }

    /**
     * Replace [source]'s downloaded list with [bytes], via a temp file
     * and a rename, so a crash mid-write can never leave a torn list
     * behind — the old file is either fully replaced or fully kept.
     */
    fun writeDownloaded(source: ListSource, bytes: ByteArray) {
        writeAtomically(fileFor(source), bytes)
    }

    /**
     * Write [bytes] to [target] so the file is never left torn: write
     * a temp file, then rename it over the target (atomic on Android).
     * If the rename ever refuses, stage the copy under a second name
     * and rename *that* — copying straight over the target is not an
     * option, because a crash mid-copy would leave half a file behind
     * (and a half-written list can still pass the sanity gate as a
     * silently weaker list). If even the staged rename fails, the old
     * file stays and the temps are cleaned up.
     */
    private fun writeAtomically(target: File, bytes: ByteArray) {
        val dir = target.parentFile ?: listsDir
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

    fun lastUpdatedMillis(): Long = prefs.getLong(KEY_LAST_UPDATED, 0L)

    fun recordUpdate(totalDomains: Int, whenMillis: Long) {
        prefs.edit()
            .putInt(KEY_DOWNLOADED_COUNT, totalDomains)
            .putLong(KEY_LAST_UPDATED, whenMillis)
            .apply()
    }

    // --- Loading ----------------------------------------------------------

    fun loadBundledBlocklist(): Blocklist =
        appContext.assets.open(BUNDLED_ASSET).bufferedReader().useLines { lines ->
            Blocklist.fromLines(lines)
        }

    /**
     * The union of every downloaded list on disk that individually
     * passes the sanity gate — or null when there is no valid
     * downloaded list, in which case the bundled list rules.
     */
    fun loadDownloadedBlocklist(): Blocklist? {
        var union: MutableSet<String>? = null
        for (source in sources()) {
            val file = savedFile(source) ?: continue
            val parsed = file.bufferedReader().useLines { lines ->
                ListValidation.parseAndValidate(lines)
            } ?: continue
            if (union == null) union = HashSet()
            union.addAll(parsed.domains)
        }
        val combined = union ?: return null
        val blocklist = Blocklist(combined)
        return if (ListValidation.isAcceptable(blocklist)) blocklist else null
    }

    /** The lists the filter should run with right now: the active
     *  blocklist (downloaded, or bundled) with the user's own custom
     *  block entries unioned in; the allowlist still wins over both. */
    fun loadEffectiveLists(): FilterLists {
        val base = loadDownloadedBlocklist() ?: loadBundledBlocklist()
        val custom = customBlockDomainSet()
        val blocklist =
            if (custom.isEmpty()) base else Blocklist(base.domains + custom)
        return FilterLists(blocklist, loadAllowlist())
    }

    data class Status(
        val activeDomains: Int,
        val usingDownloaded: Boolean,
        val lastUpdatedMillis: Long,
    )

    /** Parses list files — call from a background thread. */
    fun status(): Status {
        val downloaded = loadDownloadedBlocklist()
        return if (downloaded != null) {
            Status(downloaded.size, usingDownloaded = true, lastUpdatedMillis())
        } else {
            Status(loadBundledBlocklist().size, usingDownloaded = false, lastUpdatedMillis())
        }
    }

    // --- Allowlist --------------------------------------------------------

    fun loadAllowlist(): Allowlist {
        if (!allowlistFile.isFile) return Allowlist(emptyList())
        return allowlistFile.bufferedReader().useLines { Allowlist.fromLines(it) }
    }

    /** The user's allowlist entries, normalized and sorted, for display. */
    fun allowlistEntries(): List<String> {
        if (!allowlistFile.isFile) return emptyList()
        return allowlistFile.bufferedReader().useLines { lines ->
            Blocklist.parseEntries(lines).sorted()
        }
    }

    fun saveAllowlist(entries: Collection<String>) {
        // Entry validation, not mere normalization: an entry the
        // loader would drop (single label, reserved name) must not be
        // stored as if it were in force.
        val normalized = entries.mapNotNull { Blocklist.normalizeEntry(it) }.toSortedSet()
        val text = normalized.joinToString("\n", postfix = "\n")
        writeAtomically(allowlistFile, text.toByteArray(Charsets.UTF_8))
    }

    // --- Custom block entries (Phase 3) -------------------------------------

    /**
     * The user's own blocked domains, as a parsed entry set. Entries
     * enter ONLY through the parser's front door
     * ([Blocklist.parseEntries] / [Blocklist.normalizeEntry] — the
     * Phase 2 audit rule), so what is stored is exactly what the
     * matcher honors: nothing an entry-time check would refuse can be
     * sitting in the file pretending to work.
     */
    private fun customBlockDomainSet(): Set<String> {
        if (!customBlockFile.isFile) return emptySet()
        return customBlockFile.bufferedReader().useLines { lines ->
            Blocklist.parseEntries(lines)
        }
    }

    /** The user's custom block entries, normalized and sorted. */
    fun customBlockEntries(): List<String> = customBlockDomainSet().sorted()

    fun saveCustomBlockEntries(entries: Collection<String>) {
        val normalized = entries.mapNotNull { Blocklist.normalizeEntry(it) }.toSortedSet()
        val text = normalized.joinToString("\n", postfix = "\n")
        writeAtomically(customBlockFile, text.toByteArray(Charsets.UTF_8))
    }

    // --- App rules (Phase 3) --------------------------------------------------

    /** The user's per-app rules (blocked outright / exempt), or an
     *  empty rule set when none were ever saved. */
    fun loadAppRules(): AppRules {
        if (!appRulesFile.isFile) return AppRules()
        return appRulesFile.bufferedReader().useLines { lines -> AppRules.parse(lines) }
    }

    fun saveAppRules(rules: AppRules) {
        val text = rules.serializeLines().joinToString("\n", postfix = "\n")
        writeAtomically(appRulesFile, text.toByteArray(Charsets.UTF_8))
    }

    // --- Query log setting --------------------------------------------------

    /**
     * The query log is ON by default: it is how a user can see what
     * Sphinx questioned, it never leaves the phone, and it can be
     * turned off here at any time. (Stated in the README, plainly.)
     */
    fun queryLogEnabled(): Boolean = prefs.getBoolean(KEY_LOG_ENABLED, true)

    fun setQueryLogEnabled(enabled: Boolean) {
        prefs.edit().putBoolean(KEY_LOG_ENABLED, enabled).apply()
    }

    // --- Internals ----------------------------------------------------------

    private fun pruneOrphanFiles(current: List<ListSource>) {
        val keep = current.map { fileNameFor(it.url) }.toSet()
        listsDir.listFiles()?.forEach { file ->
            if (file.name !in keep) file.delete()
        }
    }

    private fun fileNameFor(url: String): String {
        val digest = MessageDigest.getInstance("SHA-256").digest(url.toByteArray())
        return digest.take(8).joinToString("") { "%02x".format(it) } + ".txt"
    }

    companion object {
        const val BUNDLED_ASSET = "bundled-blocklist.txt"
        private const val PREFS_NAME = "sphinx_lists"
        private const val KEY_SOURCES = "sources"
        private const val KEY_LAST_UPDATED = "last_updated"
        private const val KEY_DOWNLOADED_COUNT = "downloaded_count"
        private const val KEY_LOG_ENABLED = "query_log_enabled"
    }
}
