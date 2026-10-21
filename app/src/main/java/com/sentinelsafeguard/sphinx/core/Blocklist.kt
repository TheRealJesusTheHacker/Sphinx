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

    /** The normalized entries, as a set. Exposed so editions can union
     *  several parsed lists into one (see ListValidation / list stores). */
    val domains: Set<String> = entries.mapNotNull { normalize(it) }.toSet()

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
         * An IP literal is never a domain entry and is rejected.
         */
        fun normalize(raw: String?): String? {
            var name = raw?.trim()?.lowercase() ?: return null
            if (name.startsWith("*.")) name = name.substring(2)
            name = name.trimEnd('.')
            if (name.isEmpty()) return null
            // Labels of letters/digits/hyphens, dot-separated — anything
            // else is a junk line from a list file, not a domain.
            if (!name.matches(DOMAIN_SHAPE)) return null
            if (name.matches(IPV4_SHAPE)) return null
            return name
        }

        private val DOMAIN_SHAPE =
            Regex("^[a-z0-9]([a-z0-9-]*[a-z0-9])?(\\.[a-z0-9]([a-z0-9-]*[a-z0-9])?)*$")

        private val IPV4_SHAPE = Regex("^\\d+\\.\\d+\\.\\d+\\.\\d+$")

        private val WHITESPACE = Regex("\\s+")

        /**
         * Names that appear in hosts files as local-machine plumbing,
         * never as blockable domains. A list line naming one of these is
         * infrastructure, not an ad server, and is skipped.
         */
        private val RESERVED_NAMES = setOf(
            "localhost",
            "localhost.localdomain",
            "local",
            "broadcasthost",
            "ip6-localhost",
            "ip6-loopback",
            "ip6-localnet",
            "ip6-mcastprefix",
            "ip6-allnodes",
            "ip6-allrouters",
            "ip6-allhosts",
        )

        /**
         * Build a blocklist from list-file text. Supported shapes
         * (docs/FILTER-SPEC.md, "List files"):
         *  - "ads.example.com"                 (plain, one per line)
         *  - "*.ads.example.com"               (wildcard — same meaning)
         *  - "0.0.0.0 ads.example.com"         (hosts file: an IP literal,
         *    then one or more names; IPv6 literals work the same way)
         *  - "# comment", blank lines, and trailing "# ..." notes on a
         *    line are ignored.
         *
         * Safety rails while parsing:
         *  - Reserved local names (localhost and friends) are skipped.
         *  - Single-label entries ("com", "net") are skipped: one word
         *    would otherwise block an entire top-level domain.
         *  - Anything that doesn't normalize to a domain is skipped.
         */
        fun fromLines(lines: Sequence<String>): Blocklist = Blocklist(parseEntries(lines))

        /** The normalized entry set a list file parses to — the same
         *  rules as [fromLines], for callers (like an allowlist store)
         *  that need the entries themselves, not a matcher. */
        fun parseEntries(lines: Sequence<String>): Set<String> {
            val entries = HashSet<String>()
            for (line in lines) parseLine(line, entries)
            return entries
        }

        private fun parseLine(line: String, out: MutableSet<String>) {
            var text = line
            val hash = text.indexOf('#')
            if (hash >= 0) text = text.substring(0, hash)
            text = text.trim()
            if (text.isEmpty()) return
            val tokens = text.split(WHITESPACE)
            if (tokens.size >= 2 && isIpLiteral(tokens[0])) {
                // Hosts-file line: every token after the address is a
                // name for that address.
                for (i in 1 until tokens.size) addEntry(tokens[i], out)
            } else {
                addEntry(tokens[0], out)
            }
        }

        private fun addEntry(token: String, out: MutableSet<String>) {
            val name = normalize(token) ?: return
            if ('.' !in name) return // single label: see safety rails above
            if (name in RESERVED_NAMES) return
            out.add(name)
        }

        /** A hosts-file address token: dotted-quad IPv4, or any IPv6 form. */
        private fun isIpLiteral(token: String): Boolean =
            token.matches(IPV4_SHAPE) || ':' in token
    }
}
