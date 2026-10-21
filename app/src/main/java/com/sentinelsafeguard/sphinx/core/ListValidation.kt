package com.sentinelsafeguard.sphinx.core

/**
 * A named source a blocklist can be downloaded from. The URLs are
 * user-visible and user-editable in the app; these defaults are simply
 * where a fresh install points (docs/FILTER-SPEC.md, "List updates").
 */
data class ListSource(val name: String, val url: String) {
    companion object {
        /** Only HTTPS sources are accepted — a blocklist is a security
         *  control, so it never travels over a tamperable channel. */
        fun isAcceptableUrl(url: String): Boolean =
            url.startsWith("https://") && url.length > "https://".length

        val DEFAULTS: List<ListSource> = listOf(
            ListSource(
                "StevenBlack — ads & malware (unified hosts)",
                "https://raw.githubusercontent.com/StevenBlack/hosts/master/hosts",
            ),
            ListSource(
                "HaGeZi — Multi LIGHT (ads, trackers, telemetry)",
                "https://raw.githubusercontent.com/hagezi/dns-blocklists/main/wildcard/light.txt",
            ),
        )
    }
}

/**
 * The sanity gate a downloaded list must pass before it may replace a
 * working list (docs/FILTER-SPEC.md, "List updates"):
 *
 * A real blocklist holds thousands of domains. A download that parses
 * to fewer than [DEFAULT_MIN_DOMAINS] — an error page, a truncated
 * file, an empty response, a captive-portal login screen — is not a
 * blocklist, no matter how it arrived. Validation always happens on
 * the fully parsed list, before any swap; a failed validation changes
 * nothing.
 */
object ListValidation {

    const val DEFAULT_MIN_DOMAINS = 1_000

    fun isAcceptable(list: Blocklist, minDomains: Int = DEFAULT_MIN_DOMAINS): Boolean =
        list.size >= minDomains

    /** Parse list text and return it only if it passes the sanity gate. */
    fun parseAndValidate(
        lines: Sequence<String>,
        minDomains: Int = DEFAULT_MIN_DOMAINS,
    ): Blocklist? {
        val parsed = Blocklist.fromLines(lines)
        return if (isAcceptable(parsed, minDomains)) parsed else null
    }
}
