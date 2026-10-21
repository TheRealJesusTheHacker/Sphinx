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
    fun theGateCountsUniqueDomainsNotLines() {
        // 5,000 lines but only 10 distinct names: a flood of duplicates
        // must not inflate a junk download past the sanity floor.
        val dupes = (1..5_000).asSequence().map { "host${it % 10}.example.com" }
        assertNull(ListValidation.parseAndValidate(dupes))
    }

    @Test
    fun redirectsMustStayOnHttps() {
        val base = "https://lists.example.com/hosts.txt"
        // Ordinary hops are fine: same host, relative path, another
        // HTTPS host (a CDN or mirror).
        assertEquals(
            "https://lists.example.com/v2/hosts.txt",
            ListValidation.redirectTarget(base, "/v2/hosts.txt"),
        )
        assertEquals(
            "https://cdn.example.net/hosts.txt",
            ListValidation.redirectTarget(base, "https://cdn.example.net/hosts.txt"),
        )
        // A downgrade to plain HTTP fails the download, as does a
        // scheme-relative hop onto a non-HTTPS base resolution.
        assertNull(ListValidation.redirectTarget(base, "http://lists.example.com/hosts.txt"))
        assertNull(ListValidation.redirectTarget(base, "ftp://lists.example.com/hosts.txt"))
        // Missing or unusable Location headers fail too.
        assertNull(ListValidation.redirectTarget(base, null))
        assertNull(ListValidation.redirectTarget(base, "   "))
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
