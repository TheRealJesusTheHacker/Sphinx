package com.sentinelsafeguard.sphinx.core

/** What the user has told Sphinx to do with one app (Phase 3). */
enum class AppRuleType {
    /** The app gets no network at all while Sphinx runs. */
    BLOCKED,

    /** The app bypasses Sphinx entirely — never filtered. */
    EXCLUDED,
}

/**
 * How the Android edition must set up its capture for a given set of
 * app rules (docs/FILTER-SPEC.md, "Per-app rules"). Android routes are
 * per-VPN-interface, not per-app, so the two shapes are genuinely
 * different interfaces:
 *
 *  - [FILTER]: routes carry only the virtual DNS server — every app's
 *    DNS is questioned and nothing else enters the tunnel.
 *  - [APP_BLOCK]: at least one app is blocked outright. The interface
 *    switches to an allowlist holding only the blocked apps, with a
 *    default route, so a blocked app's traffic enters the tunnel and
 *    is dropped. Every other app bypasses the VPN (and its filtering)
 *    while this mode lasts.
 */
enum class CaptureMode {
    FILTER,
    APP_BLOCK,
}

/**
 * The user's per-app rules: which apps are blocked outright and which
 * are exempt from filtering. A package holds at most one rule —
 * setting a rule replaces any other rule for that package.
 *
 * Storage shape (one rule per line, tab-separated):
 *   `block<TAB>com.example.app`
 *   `exclude<TAB>com.example.bank`
 * Parsing is defensive, like the list parser: malformed lines and
 * names that can't be Android package names are dropped, never
 * half-applied.
 *
 * Pure Kotlin — no Android APIs. Shared by every Sphinx edition.
 */
class AppRules(
    blocked: Collection<String> = emptyList(),
    excluded: Collection<String> = emptyList(),
) {
    /** Packages the user has blocked outright. */
    val blockedPackages: Set<String> =
        blocked.mapNotNull { validPackageOrNull(it) }.toSet()

    /** Packages exempt from filtering. Never overlaps
     *  [blockedPackages]: if a name somehow arrives in both, the
     *  block wins — the stronger of the user's two instructions. */
    val excludedPackages: Set<String> =
        excluded.mapNotNull { validPackageOrNull(it) }.toSet() - blockedPackages

    val isEmpty: Boolean get() = blockedPackages.isEmpty() && excludedPackages.isEmpty()

    /** The rule in force for [packageName], or null for "no rule". */
    fun ruleFor(packageName: String): AppRuleType? = when {
        packageName in blockedPackages -> AppRuleType.BLOCKED
        packageName in excludedPackages -> AppRuleType.EXCLUDED
        else -> null
    }

    /** A copy with [packageName]'s rule set to [type] — or cleared,
     *  when [type] is null. Setting one rule clears the other. */
    fun withRule(packageName: String, type: AppRuleType?): AppRules {
        val name = validPackageOrNull(packageName) ?: return this
        val blocked = blockedPackages.toMutableSet()
        val excluded = excludedPackages.toMutableSet()
        blocked.remove(name)
        excluded.remove(name)
        when (type) {
            AppRuleType.BLOCKED -> blocked.add(name)
            AppRuleType.EXCLUDED -> excluded.add(name)
            null -> Unit
        }
        return AppRules(blocked, excluded)
    }

    /** The capture shape these rules require of the Android edition. */
    fun captureMode(): CaptureMode =
        if (blockedPackages.isEmpty()) CaptureMode.FILTER else CaptureMode.APP_BLOCK

    /** The storage lines for these rules — sorted, so the file on
     *  disk is stable and diff-friendly. */
    fun serializeLines(): List<String> =
        blockedPackages.sorted().map { "block\t$it" } +
            excludedPackages.sorted().map { "exclude\t$it" }

    override fun equals(other: Any?): Boolean =
        other is AppRules &&
            blockedPackages == other.blockedPackages &&
            excludedPackages == other.excludedPackages

    override fun hashCode(): Int = 31 * blockedPackages.hashCode() + excludedPackages.hashCode()

    override fun toString(): String =
        "AppRules(blocked=$blockedPackages, excluded=$excludedPackages)"

    companion object {
        /**
         * An Android package name: dot-separated labels (at least
         * two), each starting with a letter and otherwise letters,
         * digits, or underscores. This is the shape the platform
         * itself requires of installed apps, so anything else in a
         * stored rules file is corruption, not a rule.
         */
        private val PACKAGE_SHAPE =
            Regex("^[A-Za-z][A-Za-z0-9_]*(\\.[A-Za-z][A-Za-z0-9_]*)+$")

        fun isValidPackageName(name: String?): Boolean =
            name != null && name.matches(PACKAGE_SHAPE)

        private fun validPackageOrNull(name: String?): String? =
            name?.trim()?.takeIf { it.matches(PACKAGE_SHAPE) }

        /** Parse stored rule lines; anything unusable is skipped. */
        fun parse(lines: Sequence<String>): AppRules {
            val blocked = LinkedHashSet<String>()
            val excluded = LinkedHashSet<String>()
            for (line in lines) {
                val tab = line.indexOf('\t')
                if (tab <= 0) continue
                val name = validPackageOrNull(line.substring(tab + 1)) ?: continue
                when (line.substring(0, tab).trim().lowercase()) {
                    "block" -> {
                        excluded.remove(name)
                        blocked.add(name)
                    }
                    "exclude" -> {
                        // A block already read wins over a later
                        // exclude line for the same package.
                        if (name !in blocked) excluded.add(name)
                    }
                }
            }
            return AppRules(blocked, excluded)
        }
    }
}
