package com.sentinelsafeguard.sphinx

import java.io.File
import kotlin.math.max
import kotlin.math.min
import kotlin.math.pow
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertTrue
import org.junit.Assume.assumeTrue
import org.junit.Test

/**
 * The Sphinx palette on Android — pinned like the sibling editions
 * pin theirs.
 *
 * The canonical constants live in the Windows edition's theme
 * module: windows/src/sphinx_win/app/theme.py at Sphinx HEAD
 * c9ea4f0dfc1d (Phase 3, the "Sphinx palette HUD"). Basalt black,
 * sandstone, bronze-gold — the stone guardian's identity. Android
 * inherits that palette verbatim (res/values/colors.xml carries it
 * into Theme.Sphinx); it does not reinterpret it. The tests below
 * pin the literal set, hold every rendered text pairing at WCAG
 * 4.5:1 or better with the fleet's formula, verify the shipped
 * resources carry exactly these values, and keep purple out (that
 * exception is Beerus's alone).
 */
class PaletteTest {

    companion object {
        // Role name (as in res/values/colors.xml, minus the
        // "sphinx_" prefix) to canonical hex, verbatim from
        // windows/src/sphinx_win/app/theme.py @ c9ea4f0dfc1d.
        val CANONICAL: Map<String, String> = linkedMapOf(
            "bg" to "#0F0D0A",
            "panel" to "#171310",
            "panel_raised" to "#211A12",
            "hairline" to "#3A2F1E",
            "text" to "#ECE0C6",
            "text_faint" to "#B3A284",
            "bronze" to "#CF9A3E",
            "bronze_deep" to "#6E521F",
            "bronze_soft" to "#EAC987",
            "bronze_muted" to "#7D6740",
            "danger" to "#E5534B",
            "icon_face" to "#16120D",
        )

        // The Windows theme's constant names for the same roles —
        // used by the cross-tree agreement test below.
        val WINDOWS_NAMES: Map<String, String> = mapOf(
            "bg" to "BG",
            "panel" to "PANEL",
            "panel_raised" to "PANEL_RAISED",
            "hairline" to "HAIRLINE",
            "text" to "TEXT",
            "text_faint" to "TEXT_FAINT",
            "bronze" to "BRONZE",
            "bronze_deep" to "BRONZE_DEEP",
            "bronze_soft" to "BRONZE_SOFT",
            "bronze_muted" to "BRONZE_MUTED",
            "danger" to "DANGER",
            "icon_face" to "ICON_FACE",
        )

        // Every text/background pairing the Android UI renders,
        // named as in the Windows theme's TEXT_PAIRINGS (the
        // Android surfaces are a subset of its roles: body text
        // sits on the window, inputs and buttons on the raised
        // surface, the selection on aged bronze, hints in faint).
        val TEXT_PAIRINGS: List<Triple<String, String, String>> = listOf(
            Triple("body text on window", "text", "bg"),
            Triple("body text on panel", "text", "panel"),
            Triple("body text on raised surface", "text", "panel_raised"),
            Triple("faint text on window", "text_faint", "bg"),
            Triple("faint text on panel", "text_faint", "panel"),
            Triple("faint text on raised surface", "text_faint", "panel_raised"),
            Triple("primary button text on bronze", "text", "bronze_deep"),
            Triple("selection text on bronze", "text", "bronze_deep"),
            Triple("accent text on window", "bronze", "bg"),
            Triple("accent text on panel", "bronze", "panel"),
            Triple("bright detail text on window", "bronze_soft", "bg"),
            Triple("danger text on window", "danger", "bg"),
            Triple("danger text on panel", "danger", "panel"),
        )

        val RETIRED_HEXES = listOf("#35D07F", "#0B0F0C")

        fun locate(vararg relative: String): File? {
            val candidates = relative.flatMap { listOf(File(it), File("app/$it"), File("../$it")) }
            return candidates.firstOrNull { it.isFile }
        }

        fun luminance(hex: String): Double {
            val h = hex.removePrefix("#")
            fun linear(c: Double): Double =
                if (c <= 0.03928) c / 12.92 else ((c + 0.055) / 1.055).pow(2.4)
            val r = linear(h.substring(0, 2).toInt(16) / 255.0)
            val g = linear(h.substring(2, 4).toInt(16) / 255.0)
            val b = linear(h.substring(4, 6).toInt(16) / 255.0)
            return 0.2126 * r + 0.7152 * g + 0.0722 * b
        }

        fun contrastRatio(foreground: String, background: String): Double {
            val lf = luminance(foreground)
            val lb = luminance(background)
            return (max(lf, lb) + 0.05) / (min(lf, lb) + 0.05)
        }

        /** Hue as a fraction of the wheel, plus saturation (HSL). */
        fun hueAndSaturation(hex: String): Pair<Double, Double> {
            val h = hex.removePrefix("#")
            val r = h.substring(0, 2).toInt(16) / 255.0
            val g = h.substring(2, 4).toInt(16) / 255.0
            val b = h.substring(4, 6).toInt(16) / 255.0
            val hi = max(r, max(g, b))
            val lo = min(r, min(g, b))
            val lightness = (hi + lo) / 2
            if (hi == lo) return 0.0 to 0.0
            val d = hi - lo
            val saturation = if (lightness > 0.5) d / (2 - hi - lo) else d / (hi + lo)
            val hue = when (hi) {
                r -> ((g - b) / d + if (g < b) 6 else 0) / 6
                g -> ((b - r) / d + 2) / 6
                else -> ((r - g) / d + 4) / 6
            }
            return hue to saturation
        }
    }

    @Test
    fun everyTextPairingMeetsWcagAa() {
        for ((name, fg, bg) in TEXT_PAIRINGS) {
            val ratio = contrastRatio(CANONICAL.getValue(fg), CANONICAL.getValue(bg))
            assertTrue("$name: ${CANONICAL[fg]} on ${CANONICAL[bg]} is $ratio:1", ratio >= 4.5)
        }
    }

    @Test
    fun dangerIsTheFleetStandardRed() {
        assertEquals("#E5534B", CANONICAL.getValue("danger"))
    }

    @Test
    fun noPurpleAnywhereInThePalette() {
        assertTrue(CANONICAL.isNotEmpty())
        for ((role, hex) in CANONICAL) {
            val (hue, saturation) = hueAndSaturation(hex)
            if (saturation > 0.12) {
                // The violet band (roughly 245-310 degrees) is out
                // of bounds — that exception is Beerus's alone.
                assertFalse("$role ($hex) is purple", hue in 0.68..0.86)
            }
        }
    }

    @Test
    fun colorsXmlCarriesExactlyTheCanonicalSet() {
        val file = locate("src/main/res/values/colors.xml")
        assumeTrue("colors.xml not present from this working directory", file != null)
        val text = file!!.readText()
        val entries = Regex("""<color\s+name="sphinx_([a-z_]+)">(#[0-9A-Fa-f]{6})</color>""")
            .findAll(text).associate { it.groupValues[1] to it.groupValues[2].uppercase() }
        assertEquals(CANONICAL, entries)
    }

    @Test
    fun iconWearsThePalette() {
        val file = locate("src/main/res/drawable/ic_sphinx.xml")
        assumeTrue("ic_sphinx.xml not present from this working directory", file != null)
        val text = file!!.readText()
        val fills = Regex("""android:fillColor="(#[0-9A-Fa-f]{6})"""")
            .findAll(text).map { it.groupValues[1].uppercase() }.toList()
        // Same drawing as always — the stone face and the watchful
        // eye, in the icon's canonical tones.
        assertEquals(
            listOf(CANONICAL.getValue("icon_face"), CANONICAL.getValue("bronze"), CANONICAL.getValue("bronze")),
            fills,
        )
    }

    @Test
    fun noRetiredHexRemainsInTheUiResources() {
        val uiFiles = listOf(
            "src/main/res/values/colors.xml",
            "src/main/res/values/themes.xml",
            "src/main/res/drawable/ic_sphinx.xml",
            "src/main/res/layout/activity_main.xml",
            "src/main/res/layout/activity_app_picker.xml",
            "src/main/res/layout/app_picker_row.xml",
        )
        var checked = 0
        for (relative in uiFiles) {
            val file = locate(relative) ?: continue
            val text = file.readText().uppercase()
            for (retired in RETIRED_HEXES) {
                assertFalse("$relative still carries retired $retired", text.contains(retired))
            }
            checked++
        }
        assumeTrue("no UI resources present from this working directory", checked > 0)
    }

    @Test
    fun agreesWithTheWindowsThemeWhenTheTreeIsPresent() {
        val file = locate("windows/src/sphinx_win/app/theme.py")
        assumeTrue("windows theme not present from this working directory", file != null)
        val text = file!!.readText()
        val shipped = Regex("""^([A-Z_]+) = "(#[0-9A-Fa-f]{6})"""", RegexOption.MULTILINE)
            .findAll(text).associate { it.groupValues[1] to it.groupValues[2].uppercase() }
        for ((role, windowsName) in WINDOWS_NAMES) {
            assertEquals(
                "role $role drifted from the Windows theme's $windowsName",
                CANONICAL.getValue(role),
                shipped[windowsName],
            )
        }
    }
}
