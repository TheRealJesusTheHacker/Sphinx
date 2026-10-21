package com.sentinelsafeguard.sphinx.core

import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertNull
import org.junit.Assert.assertTrue
import org.junit.Test

class AppRulesTest {

    @Test
    fun emptyRulesUseFilterMode() {
        val rules = AppRules()
        assertTrue(rules.isEmpty)
        assertEquals(CaptureMode.FILTER, rules.captureMode())
        assertNull(rules.ruleFor("com.example.app"))
    }

    @Test
    fun excludeOnlyStillUsesFilterMode() {
        val rules = AppRules(excluded = listOf("com.example.bank"))
        assertEquals(CaptureMode.FILTER, rules.captureMode())
        assertEquals(AppRuleType.EXCLUDED, rules.ruleFor("com.example.bank"))
    }

    @Test
    fun anyBlockedAppSwitchesToAppBlockMode() {
        val rules = AppRules(blocked = listOf("com.example.game"))
        assertEquals(CaptureMode.APP_BLOCK, rules.captureMode())
        assertEquals(AppRuleType.BLOCKED, rules.ruleFor("com.example.game"))
    }

    @Test
    fun withRuleSetsSwitchesAndClears() {
        var rules = AppRules()
        rules = rules.withRule("com.example.app", AppRuleType.BLOCKED)
        assertEquals(AppRuleType.BLOCKED, rules.ruleFor("com.example.app"))

        // Setting the other rule replaces the first — never both.
        rules = rules.withRule("com.example.app", AppRuleType.EXCLUDED)
        assertEquals(AppRuleType.EXCLUDED, rules.ruleFor("com.example.app"))
        assertTrue(rules.blockedPackages.isEmpty())

        rules = rules.withRule("com.example.app", null)
        assertNull(rules.ruleFor("com.example.app"))
        assertTrue(rules.isEmpty)
    }

    @Test
    fun withRuleRefusesNamesThatCannotBePackages() {
        val rules = AppRules().withRule("not a package!", AppRuleType.BLOCKED)
        assertTrue(rules.isEmpty)
    }

    @Test
    fun blockWinsWhenANameArrivesInBothSets() {
        val rules = AppRules(
            blocked = listOf("com.example.app"),
            excluded = listOf("com.example.app", "com.example.bank"),
        )
        assertEquals(AppRuleType.BLOCKED, rules.ruleFor("com.example.app"))
        assertEquals(setOf("com.example.bank"), rules.excludedPackages)
    }

    @Test
    fun constructorDropsInvalidNames() {
        val rules = AppRules(
            blocked = listOf("com.example.ok", "singlelabel", "", "com..broken"),
        )
        assertEquals(setOf("com.example.ok"), rules.blockedPackages)
    }

    @Test
    fun serializeParseRoundTrips() {
        val rules = AppRules(
            blocked = listOf("com.zeta.app", "com.alpha.app"),
            excluded = listOf("com.example.bank"),
        )
        val lines = rules.serializeLines()
        // Sorted and stable: blocks first, each group alphabetical.
        assertEquals(
            listOf(
                "block\tcom.alpha.app",
                "block\tcom.zeta.app",
                "exclude\tcom.example.bank",
            ),
            lines,
        )
        assertEquals(rules, AppRules.parse(lines.asSequence()))
    }

    @Test
    fun parseSkipsMalformedLines() {
        val rules = AppRules.parse(
            sequenceOf(
                "",
                "no-tab-here",
                "block\t",
                "\tcom.example.app",
                "frobnicate\tcom.example.app",
                "block\tnot a package",
                "block\tcom.example.good",
                "exclude\tcom.example.bank",
            )
        )
        assertEquals(setOf("com.example.good"), rules.blockedPackages)
        assertEquals(setOf("com.example.bank"), rules.excludedPackages)
    }

    @Test
    fun parseKeepsTheBlockWhenBothLinesNameOnePackage() {
        val blockFirst = AppRules.parse(
            sequenceOf("block\tcom.example.app", "exclude\tcom.example.app")
        )
        assertEquals(AppRuleType.BLOCKED, blockFirst.ruleFor("com.example.app"))

        val excludeFirst = AppRules.parse(
            sequenceOf("exclude\tcom.example.app", "block\tcom.example.app")
        )
        assertEquals(AppRuleType.BLOCKED, excludeFirst.ruleFor("com.example.app"))
    }

    @Test
    fun packageNameShape() {
        assertTrue(AppRules.isValidPackageName("com.example.app"))
        assertTrue(AppRules.isValidPackageName("org.mozilla.firefox"))
        assertFalse(AppRules.isValidPackageName("singlelabel"))
        assertFalse(AppRules.isValidPackageName("com.example."))
        assertFalse(AppRules.isValidPackageName(".com.example"))
        assertFalse(AppRules.isValidPackageName("com.exa mple.app"))
        assertFalse(AppRules.isValidPackageName("9com.example.app"))
        assertFalse(AppRules.isValidPackageName(null))
        assertFalse(AppRules.isValidPackageName(""))
    }
}
