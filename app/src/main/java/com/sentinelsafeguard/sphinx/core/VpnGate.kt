package com.sentinelsafeguard.sphinx.core

import java.util.Base64

/**
 * VPN Gate public-nodes directory (Phase 2, TUNNEL-SPEC
 * "Public volunteer servers") — the Android edition.
 *
 * THE LICENSING STOP, stated where it governs: Android has no
 * system OpenVPN binary to invoke. The embeddable engines are
 * ics-openvpn (GPLv3) and the OpenVPN 3 core (AGPLv3); linking
 * either into the APK would end this edition's honest MIT
 * story, and the owner's approval of public nodes was NOT
 * approval of a license change. So this edition ships exactly
 * what the spec's Phase 2 Android paragraph prescribes:
 * directory + disclosure + refusal. Rows can be saved as
 * labeled OpenVPN profiles (source recorded, see
 * [SOURCE_VPNGATE]); connecting one is refused with the reason
 * named — [TunnelProfileParser.OPENVPN_CONNECT_REFUSAL] —
 * never a silent failure, never a dead button.
 *
 * This file is the pure core: feed parsing, the cache codec and
 * its age labels, and the directory decision (live / labeled
 * cache / honest empty state). It has no Android APIs and never
 * touches the network — fetching lives in lists/VpnGateFetcher
 * (HTTPS, size-capped, timeout-bounded, run off the main
 * thread by the UI) and cache storage in lists/VpnGateStore.
 * Tests feed this parser a synthetic fixture in the feed's
 * exact format; they never hit the live feed. Nothing is
 * bundled: there is no offline list.
 */
object VpnGate {

    const val FEED_URL = "https://www.vpngate.net/api/iphone/"

    /** The real feed is a few MB; a response larger than this
     *  is refused whole rather than parsed in part. */
    const val MAX_FEED_BYTES = 8 * 1024 * 1024

    /** The source label recorded for directory-imported
     *  profiles in the tunnel store. */
    const val SOURCE_VPNGATE = "vpngate"

    /**
     * The disclosure. It rides at the point of use: in the
     * directory section itself and again on a connect attempt
     * for a directory-imported profile. Normative per
     * TUNNEL-SPEC — a directory shipped without this warning,
     * in that place, is a spec violation.
     */
    const val DISCLOSURE: String =
        "These are strangers' machines, volunteered to a research " +
            "project (VPN Gate, University of Tsukuba). The operator can " +
            "see your traffic. VPN Gate states its servers keep " +
            "connection logs — your real address, the times, the server " +
            "you used — for three months or more. Fine for appearing to " +
            "be somewhere else; not for anything sensitive."

    /** Dead feed + no cache: the honest empty state. */
    const val EMPTY_STATE: String =
        "Couldn't fetch the public server list — check your " +
            "connection. Nothing is bundled; there is no offline list."

    /**
     * One row of the feed. Score and ping are the feed's
     * strings, carried verbatim — the UI labels them as VPN
     * Gate's numbers, never as Sphinx measurements.
     */
    data class Row(
        val hostName: String,
        val ip: String,
        val countryLong: String,
        val countryShort: String,
        val score: String,
        val ping: String,
        val configBase64: String,
    ) {
        /** How the row is named everywhere: in the directory,
         *  and as the imported profile's label. */
        val label: String
            get() = "Public volunteer server — $countryLong ($hostName)"

        /** The row's OpenVPN config text, or null when the
         *  feed's base64 does not decode — a stranger's
         *  malformed row is skipped, never half-imported. */
        fun configText(): String? = try {
            String(Base64.getDecoder().decode(configBase64), Charsets.UTF_8)
        } catch (e: Exception) {
            null
        }
    }

    /**
     * Parse the feed's CSV. Format (as VPN Gate publishes it):
     * comment lines start with `*`, the column row starts with
     * `#` (`#HostName,IP,Score,Ping,...,OpenVPN_ConfigData_Base64`),
     * data rows follow, and a `*` line terminates the list.
     * Rows with no config, or a config that does not decode,
     * are skipped; anything that is not this format parses to
     * no rows at all.
     */
    fun parseFeed(text: String): List<Row> {
        var header: List<String>? = null
        val dataLines = ArrayList<String>()
        var terminated = false
        for (raw in text.lines()) {
            if (terminated) break
            val line = raw.trimEnd('\r')
            if (line.isBlank()) continue
            when {
                line.startsWith("*") -> {
                    if (header != null) terminated = true
                }
                line.startsWith("#") -> header =
                    line.substring(1).split(',').map { it.trim() }
                header != null -> dataLines.add(line)
            }
        }
        val columns = header ?: return emptyList()
        val index = columns.withIndex().associate { (i, name) -> name to i }
        fun cell(parts: List<String>, name: String): String {
            val i = index[name] ?: return ""
            return if (i < parts.size) parts[i].trim() else ""
        }
        val rows = ArrayList<Row>()
        for (line in dataLines) {
            val parts = parseCsvLine(line)
            if (parts.all { it.isBlank() }) continue
            val row = Row(
                hostName = cell(parts, "HostName"),
                ip = cell(parts, "IP"),
                countryLong = cell(parts, "CountryLong"),
                countryShort = cell(parts, "CountryShort"),
                score = cell(parts, "Score"),
                ping = cell(parts, "Ping"),
                configBase64 = cell(parts, "OpenVPN_ConfigData_Base64"),
            )
            if (row.configBase64.isEmpty()) continue
            if (row.configText() == null) continue
            rows.add(row)
        }
        return rows
    }

    /** One CSV record: commas, with double-quoted fields (and
     *  `""` escapes) honored — the feed's free-text columns can
     *  carry commas inside quotes. */
    fun parseCsvLine(line: String): List<String> {
        val fields = ArrayList<String>()
        val current = StringBuilder()
        var inQuotes = false
        var i = 0
        while (i < line.length) {
            val c = line[i]
            when {
                inQuotes && c == '"' && i + 1 < line.length && line[i + 1] == '"' -> {
                    current.append('"')
                    i += 2
                }
                c == '"' -> {
                    inQuotes = !inQuotes
                    i++
                }
                c == ',' && !inQuotes -> {
                    fields.add(current.toString())
                    current.clear()
                    i++
                }
                else -> {
                    current.append(c)
                    i++
                }
            }
        }
        fields.add(current.toString())
        return fields
    }

    // --- Cache ---------------------------------------------------
    //
    // The cache is the last good feed TEXT plus its fetch time,
    // so what is re-parsed later is exactly what the feed said.
    // A stale cache is labeled with its age and never presented
    // as live; the label is computed here so the UI cannot dress
    // it up by accident.

    data class CachedFeed(val rows: List<Row>, val fetchedAtMs: Long) {
        fun ageLabel(nowMs: Long): String {
            val ageMs = maxOf(0L, nowMs - fetchedAtMs)
            val hours = ageMs / 3_600_000.0
            return if (hours < 1.0) {
                "list from less than an hour ago — the live list couldn't be fetched"
            } else {
                val rounded = Math.round(hours * 10) / 10.0
                val shown: Number =
                    if (rounded == Math.floor(rounded)) rounded.toLong() else rounded
                val unit = if (rounded == 1.0) "hour" else "hours"
                "list from $shown $unit ago — the live list couldn't be fetched"
            }
        }
    }

    private const val CACHE_HEADER_PREFIX = "fetched_at_ms="

    /** Serialize a fetched feed for app-private storage. */
    fun encodeCache(feedText: String, fetchedAtMs: Long): String =
        CACHE_HEADER_PREFIX + fetchedAtMs + "\n" + feedText

    /** Read a cache back; null when it is missing, malformed,
     *  or carries no usable rows. */
    fun decodeCache(stored: String?): CachedFeed? {
        if (stored == null) return null
        val newline = stored.indexOf('\n')
        if (newline < 0) return null
        val head = stored.substring(0, newline).trim()
        if (!head.startsWith(CACHE_HEADER_PREFIX)) return null
        val fetchedAtMs = head.removePrefix(CACHE_HEADER_PREFIX)
            .trim().toLongOrNull() ?: return null
        val rows = parseFeed(stored.substring(newline + 1))
        if (rows.isEmpty()) return null
        return CachedFeed(rows, fetchedAtMs)
    }

    // --- The directory decision ----------------------------------

    sealed class DirectoryResult {
        /** The feed answered just now; [rows] are live. */
        data class Live(val rows: List<Row>) : DirectoryResult()

        /** The feed did not answer; [cache] is shown with its
         *  age labeled, never as live. */
        data class FromCache(val cache: CachedFeed) : DirectoryResult()

        /** Dead feed and no cache: the honest empty state. */
        object Empty : DirectoryResult()
    }

    /**
     * Live first (size-capped, must parse to usable rows); on
     * any failure, the cache; with no cache, [DirectoryResult.Empty].
     * [feedText] is null when the fetch itself failed.
     */
    fun resolveDirectory(feedText: String?, cached: CachedFeed?): DirectoryResult {
        if (feedText != null &&
            feedText.toByteArray(Charsets.UTF_8).size <= MAX_FEED_BYTES
        ) {
            val rows = parseFeed(feedText)
            if (rows.isNotEmpty()) return DirectoryResult.Live(rows)
        }
        if (cached != null && cached.rows.isNotEmpty()) {
            return DirectoryResult.FromCache(cached)
        }
        return DirectoryResult.Empty
    }

    // --- Import ----------------------------------------------------

    /**
     * The config text a directory row is imported as: the
     * row's own OpenVPN config, carrying Sphinx's name comment
     * (the label) on its first line so the stored profile keeps
     * its public-server label through the store's round-trip —
     * the same comment convention as WireGuard exports. The
     * `#` line is a comment to OpenVPN; the config below it is
     * the feed's, untouched.
     */
    fun importTextFor(row: Row): String? {
        val config = row.configText() ?: return null
        return "# Sphinx profile: ${row.label}\n" + config
    }

    /**
     * The connect-attempt text for a profile: the named refusal
     * for any OpenVPN profile, with the directory disclosure in
     * front of it when the profile came from the public
     * directory — the disclosure rides again at the point of
     * use. Null for a WireGuard profile (it connects normally).
     */
    fun connectAttemptText(profile: ServerProfile, source: String?): String? {
        if (profile !is OvpnProfile) return null
        return if (source == SOURCE_VPNGATE) {
            DISCLOSURE + "\n\n" + TunnelProfileParser.OPENVPN_CONNECT_REFUSAL
        } else {
            TunnelProfileParser.OPENVPN_CONNECT_REFUSAL
        }
    }
}

/**
 * The tunnel store's profile-source bookkeeping, as a pure
 * codec so it is testable off-device: one `name<TAB>source`
 * line per profile. Names and sources are labels; a line that
 * does not decode is skipped, never fatal.
 */
object ProfileSources {

    fun encode(sources: Map<String, String>): String =
        sources.entries
            .filter { (name, source) ->
                name.isNotBlank() && source.isNotBlank() &&
                    !name.contains('\t') && !name.contains('\n') &&
                    !source.contains('\t') && !source.contains('\n')
            }
            .sortedBy { it.key }
            .joinToString("\n") { (name, source) -> "$name\t$source" }

    fun decode(stored: String?): Map<String, String> {
        if (stored.isNullOrBlank()) return emptyMap()
        val out = LinkedHashMap<String, String>()
        for (line in stored.lines()) {
            val tab = line.indexOf('\t')
            if (tab <= 0 || tab == line.lastIndex) continue
            val name = line.substring(0, tab).trim()
            val source = line.substring(tab + 1).trim()
            if (name.isNotEmpty() && source.isNotEmpty()) out[name] = source
        }
        return out
    }
}
