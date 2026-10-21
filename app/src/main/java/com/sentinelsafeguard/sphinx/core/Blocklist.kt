package com.sentinelsafeguard.sphinx.core

/**
 * Blocklist matching, per docs/FILTER-SPEC.md:
 *
 *  - Names compare case-insensitively, without a trailing dot.
 *  - A name is blocked when it equals a blocklist entry or is a
 *    subdomain of one. An entry never blocks its own parent or siblings.
 *
 * Pure Kotlin — no Android APIs. Shared by every Sphinx edition.
 */
class Blocklist(entries: Collection<String>) {

    private val domains: Set<String> = entries.mapNotNull { normalize(it) }.toSet()

    val size: Int get() = domains.size

    fun isBlocked(name: String): Boolean {
        var candidate = normalize(name) ?: return false
        while (true) {
            if (candidate in domains) return true
            val dot = candidate.indexOf('.')
            if (dot < 0) return false
            candidate = candidate.substring(dot + 1)
            if (candidate.isEmpty()) return false
        }
    }

    companion object {
        /**
         * Canonical form of a domain name, or null if the input can't be
         * one. Accepts a bare name ("ads.example.com"), a wildcard form
         * ("*.example.com" — same meaning here), any case, trailing dots.
         */
        fun normalize(raw: String?): String? {
            var name = raw?.trim()?.lowercase() ?: return null
            if (name.startsWith("*.")) name = name.substring(2)
            name = name.trimEnd('.')
            if (name.isEmpty()) return null
            // Labels of letters/digits/hyphens, dot-separated — anything
            // else is a junk line from a list file, not a domain.
            if (!name.matches(DOMAIN_SHAPE)) return null
            return name
        }

        private val DOMAIN_SHAPE =
            Regex("^[a-z0-9]([a-z0-9-]*[a-z0-9])?(\\.[a-z0-9]([a-z0-9-]*[a-z0-9])?)*$")

        /**
         * Build a blocklist from text lines. Supported line shapes:
         *  - "ads.example.com"            (plain)
         *  - "# comment" and blank lines  (ignored)
         *  - "0.0.0.0 ads.example.com"    (hosts-file shape)
         */
        fun fromLines(lines: Sequence<String>): Blocklist {
            val entries = ArrayList<String>()
            for (line in lines) {
                val trimmed = line.trim()
                if (trimmed.isEmpty() || trimmed.startsWith("#")) continue
                val tokens = trimmed.split(Regex("\\s+"))
                val candidate = when {
                    tokens.size >= 2 && isIpv4Literal(tokens[0]) -> tokens[1]
                    else -> tokens[0]
                }
                normalize(candidate)?.let { entries.add(it) }
            }
            return Blocklist(entries)
        }

        private fun isIpv4Literal(token: String): Boolean {
            val parts = token.split('.')
            return parts.size == 4 && parts.all { part ->
                part.isNotEmpty() && part.all { it.isDigit() } && part.toInt() in 0..255
            }
        }
    }
}
