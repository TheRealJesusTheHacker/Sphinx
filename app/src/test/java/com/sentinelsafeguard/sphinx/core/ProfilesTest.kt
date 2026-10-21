package com.sentinelsafeguard.sphinx.core

import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertNull
import org.junit.Assert.assertTrue
import org.junit.Test

class ProfilesTest {

    private fun homeState() = RuleState(
        appRules = AppRules(
            blocked = listOf("com.example.game"),
            excluded = listOf("com.example.bank"),
        ),
        allowlistEntries = listOf("example.com", "news.example.org"),
        customBlockEntries = listOf("ads.example.net"),
    )

    private fun kidsState() = RuleState(
        appRules = AppRules(blocked = listOf("com.example.social", "com.example.game")),
        allowlistEntries = listOf("school.example.edu"),
        customBlockEntries = emptyList(),
    )

    @Test
    fun roundTripPreservesProfilesStatesAndActive() {
        val set = ProfileSet(
            listOf(
                ProfileSet.Profile("Home", homeState()),
                ProfileSet.Profile("Kids", kidsState()),
            ),
            activeName = "Kids",
        )
        val parsed = ProfileSet.parse(set.serializeLines().asSequence())
        assertEquals(set, parsed)
        assertEquals("Kids", parsed.activeName)
        assertEquals(kidsState(), parsed.profile("Kids")!!.state)
        assertEquals(homeState(), parsed.profile("Home")!!.state)
    }

    @Test
    fun emptySetRoundTrips() {
        val set = ProfileSet()
        assertTrue(set.isEmpty)
        assertNull(set.activeName)
        assertEquals(set, ProfileSet.parse(set.serializeLines().asSequence()))
        assertEquals(set, ProfileSet.parse(emptySequence()))
    }

    @Test
    fun parseIgnoresGarbageUnknownVerbsAndOrphanLines() {
        val parsed = ProfileSet.parse(
            sequenceOf(
                "this line has no tab",
                "frobnicate\twhatever",
                "allow\torphan.example.com", // outside any section
                "profile\tHome",
                "block\tcom.example.game",
                "mystery\tline",
                "",
                "allow\texample.com",
            ),
        )
        assertEquals(1, parsed.profiles.size)
        val home = parsed.profile("Home")!!
        assertEquals(setOf("example.com"), home.state.allowlistEntries)
        assertEquals(AppRuleType.BLOCKED, home.state.appRules.ruleFor("com.example.game"))
    }

    @Test
    fun duplicateProfileNamesFirstWins() {
        val parsed = ProfileSet.parse(
            sequenceOf(
                "profile\tHome",
                "allow\tfirst.example.com",
                "profile\tHome",
                "allow\tsecond.example.com",
            ),
        )
        assertEquals(1, parsed.profiles.size)
        assertEquals(setOf("first.example.com"), parsed.profile("Home")!!.state.allowlistEntries)
    }

    @Test
    fun activePointingAtMissingProfileIsDropped() {
        val parsed = ProfileSet.parse(
            sequenceOf(
                "active\tGhost",
                "profile\tHome",
                "allow\texample.com",
            ),
        )
        assertNull(parsed.activeName)
        assertNull(parsed.activeProfile)
    }

    @Test
    fun entriesPassThroughTheParserRails() {
        // Junk offered as entries must be dropped by the same rails
        // the list parser applies: no single labels (they would
        // block a whole TLD), no reserved names, no bad packages.
        val state = RuleState(
            appRules = AppRules.parse(
                sequenceOf("block\tnot a package", "block\tcom.example.ok"),
            ),
            allowlistEntries = listOf("com", "localhost", "EXAMPLE.com.", "ok.example.org"),
            customBlockEntries = listOf("*.wild.example.net", "127.0.0.1"),
        )
        assertEquals(setOf("example.com", "ok.example.org"), state.allowlistEntries)
        assertEquals(setOf("wild.example.net"), state.customBlockEntries)
        assertEquals(AppRuleType.BLOCKED, state.appRules.ruleFor("com.example.ok"))
        assertNull(state.appRules.ruleFor("not a package"))
    }

    @Test
    fun blockStillWinsInsideProfileState() {
        val state = RuleState.parse(
            sequenceOf(
                "exclude\tcom.example.app",
                "block\tcom.example.app",
            ),
        )
        assertEquals(AppRuleType.BLOCKED, state.appRules.ruleFor("com.example.app"))
    }

    @Test
    fun withProfileAddsReplacesInPlaceAndRefusesBadNames() {
        var set = ProfileSet()
        set = set.withProfile(ProfileSet.Profile("Home", homeState()))
        set = set.withProfile(ProfileSet.Profile("Kids", kidsState()))
        assertEquals(listOf("Home", "Kids"), set.profiles.map { it.name })

        // Replacing keeps the position and swaps the state.
        val changed = kidsState().let {
            RuleState(it.appRules, it.allowlistEntries + "extra.example.com", it.customBlockEntries)
        }
        set = set.withProfile(ProfileSet.Profile("Kids", changed))
        assertEquals(listOf("Home", "Kids"), set.profiles.map { it.name })
        assertEquals(changed, set.profile("Kids")!!.state)

        // An unusable name changes nothing.
        assertEquals(set, set.withProfile(ProfileSet.Profile("  ", homeState())))
        assertEquals(set, set.withProfile(ProfileSet.Profile("bad\tname", homeState())))
    }

    @Test
    fun withoutProfileClearsActiveOnlyWhenItWasTheActiveOne() {
        var set = ProfileSet(
            listOf(
                ProfileSet.Profile("Home", homeState()),
                ProfileSet.Profile("Kids", kidsState()),
            ),
            activeName = "Home",
        )
        set = set.withoutProfile("Kids")
        assertEquals("Home", set.activeName)
        assertEquals(listOf("Home"), set.profiles.map { it.name })

        set = set.withoutProfile("Home")
        assertTrue(set.isEmpty)
        assertNull(set.activeName)

        // Removing a name that isn't there is a no-op.
        val other = ProfileSet(listOf(ProfileSet.Profile("Home", homeState())), "Home")
        assertEquals(other, other.withoutProfile("Nope"))
    }

    @Test
    fun withActiveRequiresAnExistingProfile() {
        val set = ProfileSet(listOf(ProfileSet.Profile("Home", homeState())))
        assertEquals("Home", set.withActive("Home").activeName)
        assertEquals(set, set.withActive("Ghost"))
        assertNull(set.withActive("Home").withActive(null).activeName)
    }

    @Test
    fun profileNameValidation() {
        assertTrue(ProfileSet.isValidProfileName("Home"))
        assertTrue(ProfileSet.isValidProfileName("Kids' stuff 2"))
        assertFalse(ProfileSet.isValidProfileName(null))
        assertFalse(ProfileSet.isValidProfileName(""))
        assertFalse(ProfileSet.isValidProfileName("   "))
        assertFalse(ProfileSet.isValidProfileName("x".repeat(41)))
        assertTrue(ProfileSet.isValidProfileName("x".repeat(40)))
        assertFalse(ProfileSet.isValidProfileName("has\ttab"))
        assertFalse(ProfileSet.isValidProfileName("has\nnewline"))
    }

    @Test
    fun sectionWithInvalidNameIsSkippedEntirely() {
        val parsed = ProfileSet.parse(
            sequenceOf(
                "profile\t",
                "allow\tlost.example.com",
                "profile\tKept",
                "allow\tkept.example.com",
            ),
        )
        assertEquals(listOf("Kept"), parsed.profiles.map { it.name })
        assertEquals(setOf("kept.example.com"), parsed.profile("Kept")!!.state.allowlistEntries)
    }
}
