package com.sentinelsafeguard.sphinx.lists

import com.sentinelsafeguard.sphinx.core.Blocklist
import com.sentinelsafeguard.sphinx.core.ListSource
import com.sentinelsafeguard.sphinx.core.ListValidation
import java.io.ByteArrayOutputStream
import java.net.HttpURLConnection
import java.net.URL

/**
 * Downloads fresh copies of the configured blocklists and swaps them
 * in — carefully (docs/FILTER-SPEC.md, "List updates"):
 *
 *  1. Every source is fetched over HTTPS and fully parsed.
 *  2. A source whose download fails, or whose contents don't parse to
 *     a sane list, keeps its previous downloaded copy. It never
 *     replaces a good list with a bad download.
 *  3. The would-be new blocklist (fresh downloads plus kept copies)
 *     must pass the sanity gate as a whole before anything on disk
 *     changes. Only then are the staged files written (each by
 *     temp-file + rename) and the update recorded.
 *
 * If the whole update can't pass the gate, nothing is written and the
 * working lists are exactly what they were. Blocking to call — run it
 * from a background thread.
 */
class ListUpdater(private val store: ListStore) {

    data class SourceOutcome(
        val source: ListSource,
        val refreshed: Boolean,
        val domains: Int,
        val note: String?,
    )

    data class Result(
        val success: Boolean,
        val totalDomains: Int,
        val outcomes: List<SourceOutcome>,
    )

    fun updateAll(nowMillis: Long): Result {
        val outcomes = ArrayList<SourceOutcome>()
        val stagedBytes = HashMap<ListSource, ByteArray>()
        val union = HashSet<String>()

        for (source in store.sources()) {
            val bytes = download(source.url)
            val parsed = bytes?.let {
                ListValidation.parseAndValidate(it.decodeToString().lineSequence())
            }
            when {
                bytes == null -> {
                    val kept = keepExisting(source, union)
                    outcomes += SourceOutcome(source, false, kept,
                        "download failed — kept the previous copy")
                }
                parsed == null -> {
                    val kept = keepExisting(source, union)
                    outcomes += SourceOutcome(source, false, kept,
                        "download didn't parse as a blocklist — kept the previous copy")
                }
                else -> {
                    stagedBytes[source] = bytes
                    union.addAll(parsed.domains)
                    outcomes += SourceOutcome(source, true, parsed.size, null)
                }
            }
        }

        val combined = Blocklist(union)
        if (!ListValidation.isAcceptable(combined)) {
            // The gate: nothing was written above, so the working lists
            // are untouched. Report failure with per-source detail.
            return Result(success = false, totalDomains = 0, outcomes = outcomes)
        }

        if (stagedBytes.isEmpty()) {
            // Every source failed and the gate passed only on copies
            // already on disk. Nothing was downloaded, so this is a
            // failed update — and a failed update changes nothing,
            // including the recorded last-updated time.
            return Result(success = false, totalDomains = 0, outcomes = outcomes)
        }

        for ((source, bytes) in stagedBytes) {
            store.writeDownloaded(source, bytes)
        }
        store.recordUpdate(combined.size, nowMillis)
        return Result(success = true, totalDomains = combined.size, outcomes = outcomes)
    }

    /** Add [source]'s previously downloaded list, if any, to [union]. */
    private fun keepExisting(source: ListSource, union: MutableSet<String>): Int {
        val file = store.savedFile(source) ?: return 0
        val parsed = file.bufferedReader().useLines { lines ->
            ListValidation.parseAndValidate(lines)
        } ?: return 0
        union.addAll(parsed.domains)
        return parsed.size
    }

    /**
     * Fetch [url] over HTTPS; null on any failure or an oversized body.
     *
     * Redirects are followed by hand, at most [MAX_REDIRECTS], and every
     * hop is checked with [ListValidation.redirectTarget]: a download
     * that starts on HTTPS must stay on HTTPS. The platform's automatic
     * redirect handling is not trusted to refuse an HTTPS → HTTP
     * downgrade on every Android version, and a downgraded hop would
     * let anyone on the network path substitute a different list.
     */
    private fun download(url: String): ByteArray? {
        if (!ListSource.isAcceptableUrl(url)) return null
        var current = url
        var hops = 0
        while (true) {
            var connection: HttpURLConnection? = null
            try {
                connection = URL(current).openConnection() as HttpURLConnection
                connection.connectTimeout = CONNECT_TIMEOUT_MS
                connection.readTimeout = READ_TIMEOUT_MS
                connection.instanceFollowRedirects = false
                connection.setRequestProperty("User-Agent", USER_AGENT)
                val code = connection.responseCode
                if (code == HttpURLConnection.HTTP_OK) {
                    val out = ByteArrayOutputStream()
                    val buffer = ByteArray(64 * 1024)
                    connection.inputStream.use { input ->
                        while (true) {
                            val read = input.read(buffer)
                            if (read < 0) break
                            if (out.size() + read > MAX_LIST_BYTES) return null
                            out.write(buffer, 0, read)
                        }
                    }
                    return out.toByteArray()
                }
                if (code in REDIRECT_CODES && hops < MAX_REDIRECTS) {
                    current = ListValidation.redirectTarget(
                        current,
                        connection.getHeaderField("Location"),
                    ) ?: return null
                    hops++
                    continue
                }
                return null
            } catch (e: Exception) {
                return null
            } finally {
                connection?.disconnect()
            }
        }
    }

    private fun ByteArray.decodeToString(): String = toString(Charsets.UTF_8)

    companion object {
        private const val CONNECT_TIMEOUT_MS = 15_000
        private const val READ_TIMEOUT_MS = 30_000
        private const val MAX_LIST_BYTES = 32 * 1024 * 1024
        private const val MAX_REDIRECTS = 5
        private val REDIRECT_CODES = setOf(301, 302, 303, 307, 308)
        private const val USER_AGENT = "Sphinx/0.2 (Android blocklist update)"
    }
}
