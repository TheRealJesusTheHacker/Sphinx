package com.sentinelsafeguard.sphinx.core

import org.junit.Assert.assertEquals
import org.junit.Assert.assertNotNull
import org.junit.Assert.assertNull
import org.junit.Assert.assertTrue
import org.junit.Test

class ListValidationTest {

    private fun syntheticList(count: Int): Sequence<String> =
        (1..count).asSequence().map { "host$it.ads.example.com" }

    @Test
    fun aRealSizedListPasses() {
        val parsed = ListValidation.parseAndValidate(syntheticList(5_000))
        assertNotNull(parsed)
        assertEquals(5_000, parsed!!.size)
    }

    @Test
    fun anEmptyDownloadIsRejected() {
        assertNull(ListValidation.parseAndValidate(emptySequence()))
        assertNull(ListValidation.parseAndValidate(sequenceOf("", "   ", "# only comments")))
    }

    @Test
    fun anErrorPageIsRejected() {
        // What a 404 page, a captive portal, or a proxy error looks like
        // after parsing: a handful of junk tokens, nowhere near a list.
        val errorPage = sequenceOf(
            "<html>", "<head>", "<title>404", "Not", "Found", "</title>", "</head>",
        )
        assertNull(ListValidation.parseAndValidate(errorPage))
    }

    @Test
    fun aTruncatedListIsRejected() {
        // A download cut short keeps only the first lines — far below
        // the sanity floor, so the working list stays untouched.
        assertNull(ListValidation.parseAndValidate(syntheticList(50)))
    }

    @Test
    fun theFloorIsConfigurable() {
        val small = ListValidation.parseAndValidate(syntheticList(50), minDomains = 10)
        assertNotNull(small)
        assertEquals(50, small!!.size)
    }

    @Test
    fun defaultSourcesAreHttpsAndReputable() {
        assertTrue(ListValidation.DEFAULT_MIN_DOMAINS >= 1_000)
        assertTrue(ListSource.DEFAULTS.isNotEmpty())
        for (source in ListSource.DEFAULTS) {
            assertTrue(source.url, ListSource.isAcceptableUrl(source.url))
        }
        assertTrue(ListSource.isAcceptableUrl("https://example.com/list.txt"))
        assertTrue(!ListSource.isAcceptableUrl("http://example.com/list.txt"))
        assertTrue(!ListSource.isAcceptableUrl("https://"))
    }
}
