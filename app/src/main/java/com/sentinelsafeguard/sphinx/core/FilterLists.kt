package com.sentinelsafeguard.sphinx.core

/**
 * The allowlist: names the user has said never to block.
 *
 * Matching uses the exact same walk as the blocklist (a name is covered
 * when it, or any parent of it, is listed) — see docs/FILTER-SPEC.md,
 * matching rule 5. Pure Kotlin, shared by every edition.
 */
class Allowlist(entries: Collection<String>) {

    private val matcher = Blocklist(entries)

    val size: Int get() = matcher.size

    /** True when [name] or any parent of it is on the allowlist. */
    fun covers(name: String): Boolean = matcher.isBlocked(name)

    companion object {
        /** Parse allowlist entries from list-file text — same line
         *  rules as the blocklist (see [Blocklist.parseEntries]). */
        fun fromLines(lines: Sequence<String>): Allowlist =
            Allowlist(Blocklist.parseEntries(lines))
    }
}

/**
 * The pair of lists a filter actually runs with, and the one decision
 * it makes per query (docs/FILTER-SPEC.md):
 *
 *  - Allowlist wins: a covered name is never blocked, even when a
 *    blocklist entry covers it too.
 *  - Otherwise the blocklist decides.
 */
class FilterLists(
    val blocklist: Blocklist,
    val allowlist: Allowlist,
) {
    fun isBlocked(name: String): Boolean {
        if (allowlist.covers(name)) return false
        return blocklist.isBlocked(name)
    }
}
