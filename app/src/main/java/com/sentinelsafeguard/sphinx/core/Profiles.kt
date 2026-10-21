package com.sentinelsafeguard.sphinx.core

/**
 * One snapshot of the user's own rule state — what a profile captures
 * (Phase 4): the per-app rules, the allowlist, and the user's custom
 * block entries.
 *
 * What a profile does NOT capture: the blocklists themselves and
 * their sources. Every profile questions with the same lists; a
 * profile is the set of choices the user made on top of them, so
 * switching profiles never changes which downloaded lists are in
 * force, and a list update never disturbs a profile.
 *
 * Entry discipline matches the rest of the core: allowlist and
 * custom entries are normalized through the parser's front door
 * ([Blocklist.normalizeEntry]) and package names through the
 * [AppRules] shape, so a stored state always does what it appears
 * to do. Pure Kotlin — no Android APIs.
 */
class RuleState(
    val appRules: AppRules = AppRules(),
    allowlistEntries: Collection<String> = emptyList(),
    customBlockEntries: Collection<String> = emptyList(),
) {
    /** Domains that are never blocked while this state is live. */
    val allowlistEntries: Set<String> =
        allowlistEntries.mapNotNull { Blocklist.normalizeEntry(it) }.toSet()

    /** Domains the user blocks on top of every list. */
    val customBlockEntries: Set<String> =
        customBlockEntries.mapNotNull { Blocklist.normalizeEntry(it) }.toSet()

    val isEmpty: Boolean
        get() = appRules.isEmpty && allowlistEntries.isEmpty() &&
            customBlockEntries.isEmpty()

    /** The storage lines for this state — sorted, so the file on
     *  disk is stable and diff-friendly. */
    fun serializeLines(): List<String> =
        appRules.serializeLines() +
            allowlistEntries.sorted().map { "allow\t$it" } +
            customBlockEntries.sorted().map { "custom\t$it" }

    override fun equals(other: Any?): Boolean =
        other is RuleState &&
            appRules == other.appRules &&
            allowlistEntries == other.allowlistEntries &&
            customBlockEntries == other.customBlockEntries

    override fun hashCode(): Int {
        var result = appRules.hashCode()
        result = 31 * result + allowlistEntries.hashCode()
        result = 31 * result + customBlockEntries.hashCode()
        return result
    }

    override fun toString(): String =
        "RuleState(appRules=$appRules, allowlist=$allowlistEntries, " +
            "custom=$customBlockEntries)"

    companion object {
        /**
         * Parse one state's lines (the shape [serializeLines]
         * writes). Defensive, like every parser in this core:
         * unknown verbs and unusable entries are skipped, never
         * half-applied.
         */
        fun parse(lines: Sequence<String>): RuleState {
            val appLines = ArrayList<String>()
            val allowRaw = ArrayList<String>()
            val customRaw = ArrayList<String>()
            for (line in lines) {
                val tab = line.indexOf('\t')
                if (tab <= 0) continue
                val value = line.substring(tab + 1)
                when (line.substring(0, tab).trim().lowercase()) {
                    "block", "exclude" -> appLines.add(line)
                    "allow" -> allowRaw.add(value)
                    "custom" -> customRaw.add(value)
                }
            }
            return RuleState(
                appRules = AppRules.parse(appLines.asSequence()),
                allowlistEntries = Blocklist.parseEntries(allowRaw.asSequence()),
                customBlockEntries = Blocklist.parseEntries(customRaw.asSequence()),
            )
        }
    }
}

/**
 * The user's named profiles (Phase 4) plus which one is active.
 *
 * The profiles are snapshots held in one store; the *live* rule
 * state (the store files the filter actually reads) is separate.
 * Switching profiles copies a snapshot into the live state and
 * applies it through the ordinary restart path. Edits to the live
 * state while a profile is active are written through to that
 * profile by the store, so the active profile always describes the
 * rules in force — a profile is the configuration, not a museum
 * copy that silently drifts from it.
 *
 * Storage shape (one directive per line, tab-separated):
 * ```
 * active<TAB>Home
 * profile<TAB>Home
 * block<TAB>com.example.game
 * allow<TAB>example.com
 * profile<TAB>Kids
 * ...
 * ```
 * Parsing is defensive: a malformed file degrades to the profiles
 * that do parse — and, worst case, to no profiles at all. It can
 * never degrade to a wiped live ruleset, because profiles and live
 * state are different stores and the live state is only ever
 * overwritten by an explicit switch.
 *
 * Pure Kotlin — no Android APIs. Shared by every Sphinx edition.
 */
class ProfileSet(
    profiles: List<Profile> = emptyList(),
    activeName: String? = null,
) {
    data class Profile(val name: String, val state: RuleState)

    /** The stored profiles, in stored order. Names are validated
     *  and deduplicated (first wins), like every other parser in
     *  this core. */
    val profiles: List<Profile>

    /** The active profile's name — kept only when it names a
     *  profile that exists. */
    val activeName: String?

    init {
        val seen = HashSet<String>()
        val kept = ArrayList<Profile>()
        for (profile in profiles) {
            val name = profile.name.trim()
            if (!isValidProfileName(name)) continue
            if (!seen.add(name)) continue
            kept.add(Profile(name, profile.state))
        }
        this.profiles = kept
        this.activeName = activeName?.trim()?.takeIf { candidate ->
            kept.any { it.name == candidate }
        }
    }

    val isEmpty: Boolean get() = profiles.isEmpty()

    /** The profile called [name], or null. */
    fun profile(name: String): Profile? = profiles.firstOrNull { it.name == name.trim() }

    /** The active profile, or null when the live rules are not
     *  under any profile. */
    val activeProfile: Profile? get() = activeName?.let { profile(it) }

    /** A copy with [profile] added, or replacing the same-named
     *  profile in place (its position in the list is kept). An
     *  unusable name changes nothing. Does not touch which profile
     *  is active. */
    fun withProfile(profile: Profile): ProfileSet {
        val name = profile.name.trim()
        if (!isValidProfileName(name)) return this
        val replacement = Profile(name, profile.state)
        val index = profiles.indexOfFirst { it.name == name }
        val next = if (index >= 0) {
            profiles.toMutableList().also { it[index] = replacement }
        } else {
            profiles + replacement
        }
        return ProfileSet(next, activeName)
    }

    /** A copy without the profile called [name]. Removing the
     *  active profile clears the active marker — the live rules
     *  themselves are untouched; they simply stop being "under"
     *  a profile. */
    fun withoutProfile(name: String): ProfileSet {
        val target = name.trim()
        if (profiles.none { it.name == target }) return this
        return ProfileSet(
            profiles.filter { it.name != target },
            if (activeName == target) null else activeName,
        )
    }

    /** A copy with a different active profile. [name] must name an
     *  existing profile, or be null to clear the marker; anything
     *  else changes nothing. */
    fun withActive(name: String?): ProfileSet {
        if (name == null) return ProfileSet(profiles, null)
        val target = name.trim()
        if (profiles.none { it.name == target }) return this
        return ProfileSet(profiles, target)
    }

    /** The storage lines for this set — the active marker first,
     *  then each profile's section. */
    fun serializeLines(): List<String> {
        val lines = ArrayList<String>()
        if (activeName != null) lines.add("active\t$activeName")
        for (profile in profiles) {
            lines.add("profile\t${profile.name}")
            lines.addAll(profile.state.serializeLines())
        }
        return lines
    }

    override fun equals(other: Any?): Boolean =
        other is ProfileSet &&
            profiles == other.profiles &&
            activeName == other.activeName

    override fun hashCode(): Int = 31 * profiles.hashCode() + (activeName?.hashCode() ?: 0)

    override fun toString(): String =
        "ProfileSet(profiles=${profiles.map { it.name }}, active=$activeName)"

    companion object {
        /** A profile name: short, printable, no format-breaking
         *  characters (tab/newline would corrupt the line format).
         *  Anything else — spaces, punctuation, emoji — is the
         *  user's business. */
        fun isValidProfileName(name: String?): Boolean {
            val trimmed = name?.trim() ?: return false
            if (trimmed.isEmpty() || trimmed.length > 40) return false
            return trimmed.none { it.isISOControl() }
        }

        /**
         * Parse a stored profile file. Sections open at
         * `profile<TAB>name`; state lines belong to the section
         * above them; lines outside a section, sections with an
         * unusable name, and later sections reusing a name are all
         * ignored (first profile of a name wins). The last valid
         * `active<TAB>name` line is the candidate marker — the
         * constructor keeps it only if that profile exists.
         */
        fun parse(lines: Sequence<String>): ProfileSet {
            var activeCandidate: String? = null
            val found = ArrayList<Profile>()
            val seen = HashSet<String>()
            var currentName: String? = null
            var currentLines = ArrayList<String>()

            fun closeSection() {
                val name = currentName ?: return
                found.add(Profile(name, RuleState.parse(currentLines.asSequence())))
                currentName = null
                currentLines = ArrayList()
            }

            for (line in lines) {
                val tab = line.indexOf('\t')
                if (tab <= 0) continue
                val verb = line.substring(0, tab).trim().lowercase()
                val value = line.substring(tab + 1).trim()
                when (verb) {
                    "active" -> if (isValidProfileName(value)) activeCandidate = value
                    "profile" -> {
                        closeSection()
                        if (isValidProfileName(value) && seen.add(value)) {
                            currentName = value
                        }
                    }
                    "block", "exclude", "allow", "custom" -> {
                        if (currentName != null) currentLines.add(line)
                    }
                    // Unknown directives are ignored, never fatal.
                }
            }
            closeSection()
            return ProfileSet(found, activeCandidate)
        }
    }
}
