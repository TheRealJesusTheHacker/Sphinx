package com.sentinelsafeguard.sphinx.core

import java.io.File
import java.util.Base64
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertNotNull
import org.junit.Assert.assertNull
import org.junit.Assert.assertTrue
import org.junit.Assume.assumeTrue
import org.junit.Test

/**
 * VPN Gate public-nodes directory (Phase 2, TUNNEL-SPEC):
 * the feed parser against a synthetic fixture in the feed's
 * exact format (marked fixture — these tests NEVER hit the
 * live feed), cache-age labeling, the dead-feed empty state,
 * disclosure presence, the named connect refusal (including
 * for directory-imported profiles), and the store's
 * source-label bookkeeping.
 */
class VpnGateTest {

    companion object {
        // --- synthetic fixture, in the feed's exact format ---
        private const val FIXTURE_CONFIG =
            "client\ndev tun\nproto udp\nremote fixture-node.example.org 1194\n" +
                "nobind\n" +
                "<ca>\n-----BEGIN CERTIFICATE-----\nFIXTURE-CERT-NOT-REAL\n" +
                "-----END CERTIFICATE-----\n</ca>\n"

        private val FIXTURE_B64: String =
            Base64.getEncoder().encodeToString(FIXTURE_CONFIG.toByteArray(Charsets.UTF_8))

        private val FIXTURE_FEED: String =
            "*VPN Gate API*\n" +
                "*https://www.vpngate.net/api/iphone/*\n" +
                "#HostName,IP,Score,Ping,Speed,CountryLong,CountryShort," +
                "NumVpnSessions,Uptime,TotalUsers,TotalTraffic,LogType,Operator," +
                "Message,OpenVPN_ConfigData_Base64\n" +
                "fixture1,203.0.113.10,100,20,1000000,Fixtureland,FL,1,1000,1,1000,2w,fixture-op,,$FIXTURE_B64\n" +
                "fixture2,203.0.113.11,90,30,900000,Otherland,OL,1,1000,1,1000,2w,fixture-op,,$FIXTURE_B64\n" +
                "fixture-bad,203.0.113.12,1,1,1,Badland,BL,1,1,1,1,2w,fixture-op,,!!!not-base64!!!\n" +
                "*\n"

        private const val NOW = 1_700_000_000_000L

        private fun locate(relative: String): File? {
            val candidates = listOf(File(relative), File("app/$relative"), File("../$relative"))
            return candidates.firstOrNull { it.isFile }
        }
    }

    @Test
    fun feedParserReadsFixtureRowsInTheFeedsExactFormat() {
        val rows = VpnGate.parseFeed(FIXTURE_FEED)
        // The malformed-base64 row is skipped; the two good rows parse.
        assertEquals(2, rows.size)
        val first = rows[0]
        assertEquals("fixture1", first.hostName)
        assertEquals("203.0.113.10", first.ip)
        assertEquals("Fixtureland", first.countryLong)
        assertEquals("FL", first.countryShort)
        assertEquals("100", first.score)
        assertEquals("20", first.ping)
        assertEquals(
            "Public volunteer server — Fixtureland (fixture1)",
            first.label,
        )
        val config = first.configText()
        assertNotNull(config)
        assertTrue(config!!.contains("fixture-node.example.org"))
        // The row's config is an ordinary OpenVPN profile record.
        val parsed = TunnelProfileParser.parse(config)
        assertTrue(parsed is TunnelParseResult.Valid)
        assertEquals(
            "openvpn",
            (parsed as TunnelParseResult.Valid).profile.protocol,
        )
    }

    @Test
    fun feedParserRejectsGarbage() {
        assertTrue(VpnGate.parseFeed("not a feed at all").isEmpty())
        assertTrue(VpnGate.parseFeed("").isEmpty())
        assertTrue(VpnGate.parseFeed("*only comments*\n*more*\n").isEmpty())
    }

    @Test
    fun cacheCodecRoundTripsRowsAndFetchTime() {
        val stored = VpnGate.encodeCache(FIXTURE_FEED, NOW)
        val cached = VpnGate.decodeCache(stored)
        assertNotNull(cached)
        assertEquals(NOW, cached!!.fetchedAtMs)
        assertEquals(2, cached.rows.size)
        assertEquals("fixture1", cached.rows[0].hostName)
        // Malformed caches decode to nothing, never to a guess.
        assertNull(VpnGate.decodeCache(null))
        assertNull(VpnGate.decodeCache("no header here"))
        assertNull(VpnGate.decodeCache("fetched_at_ms=abc\n$FIXTURE_FEED"))
        assertNull(VpnGate.decodeCache("fetched_at_ms=$NOW\ngarbage"))
    }

    @Test
    fun cacheAgeIsLabeledAndNeverPresentedAsLive() {
        val rows = VpnGate.parseFeed(FIXTURE_FEED)
        val threeHoursAgo = VpnGate.CachedFeed(rows, NOW - 3 * 3_600_000L)
        val label = threeHoursAgo.ageLabel(NOW)
        assertTrue(label.contains("3 hours ago"))
        assertTrue(label.contains("couldn't be fetched"))
        val fresh = VpnGate.CachedFeed(rows, NOW - 10 * 60_000L)
        assertTrue(fresh.ageLabel(NOW).contains("less than an hour ago"))
        val oneHour = VpnGate.CachedFeed(rows, NOW - 3_600_000L)
        assertTrue(oneHour.ageLabel(NOW).contains("1 hour ago"))
    }

    @Test
    fun directoryResolutionIsLiveThenLabeledCacheThenHonestEmpty() {
        val cached = VpnGate.decodeCache(VpnGate.encodeCache(FIXTURE_FEED, NOW - 7_200_000L))

        val live = VpnGate.resolveDirectory(FIXTURE_FEED, cached)
        assertTrue(live is VpnGate.DirectoryResult.Live)
        assertEquals(2, (live as VpnGate.DirectoryResult.Live).rows.size)

        // Dead feed + cache: the cache, labeled — never live.
        val fromCache = VpnGate.resolveDirectory(null, cached)
        assertTrue(fromCache is VpnGate.DirectoryResult.FromCache)
        assertEquals(2, (fromCache as VpnGate.DirectoryResult.FromCache).cache.rows.size)

        // Dead feed + no cache: the honest empty state.
        assertTrue(VpnGate.resolveDirectory(null, null) is VpnGate.DirectoryResult.Empty)
        assertTrue(VpnGate.resolveDirectory("garbage", null) is VpnGate.DirectoryResult.Empty)
        assertTrue(VpnGate.EMPTY_STATE.contains("Couldn't fetch the public server list"))
        assertTrue(VpnGate.EMPTY_STATE.contains("Nothing is bundled; there is no offline list."))

        // An oversized response is refused whole, never parsed in part.
        val oversized = FIXTURE_FEED + "x".repeat(VpnGate.MAX_FEED_BYTES)
        assertTrue(VpnGate.resolveDirectory(oversized, null) is VpnGate.DirectoryResult.Empty)
    }

    @Test
    fun disclosureIsPresentInCodeAndInTheShippedStrings() {
        // The normative disclosure, in the core constant the UI renders.
        assertTrue(VpnGate.DISCLOSURE.contains("strangers' machines"))
        assertTrue(VpnGate.DISCLOSURE.contains("VPN Gate, University of Tsukuba"))
        assertTrue(VpnGate.DISCLOSURE.contains("The operator can see your traffic."))
        assertTrue(VpnGate.DISCLOSURE.contains("three months or more"))
        assertTrue(VpnGate.DISCLOSURE.contains("not for anything sensitive"))

        // And in the shipped string resources (the section's copy).
        val file = locate("src/main/res/values/strings.xml")
        assumeTrue("strings.xml not present from this working directory", file != null)
        val text = file!!.readText()
        assertTrue(text.contains("section_vpngate"))
        assertTrue(text.contains("University of Tsukuba"))
        assertTrue(text.contains("three months or more"))
        assertTrue(text.contains("no offline list"))
        // The Phase 1 VPN disclosures stand untouched beside it.
        assertTrue(text.contains("vpn_disclosure"))
        assertTrue(text.contains("vpn_openvpn_note"))
        assertTrue(text.contains("vpn_blocker_gap_note"))
    }

    @Test
    fun connectOnAnOpenVpnProfileYieldsTheNamedRefusal() {
        // The refusal names the reason, in plain language.
        val refusal = TunnelProfileParser.OPENVPN_CONNECT_REFUSAL
        assertTrue(refusal.contains("can't connect OpenVPN profiles"))
        assertTrue(refusal.contains("refused"))
        assertTrue(refusal.contains("no built-in OpenVPN program"))
        assertTrue(refusal.contains("GPL/AGPL"))
        assertTrue(refusal.contains("MIT license"))
        assertTrue(refusal.contains("belongs to Sentinel"))
        assertTrue(refusal.contains("WireGuard profiles connect normally"))

        // A user's own OpenVPN profile: the refusal, alone.
        val own = (TunnelProfileParser.parse(FIXTURE_CONFIG)
            as TunnelParseResult.Valid).profile
        assertEquals(refusal, VpnGate.connectAttemptText(own, null))

        // A WireGuard profile: no refusal — it connects normally.
        val wgText = TunnelProfileParser.buildLocalConfigText(
            name = "WG",
            privateKey = "hI9byVWLK8639iOPJ8Z3ej9sp4rhqOdnHQ3pfp0N35s=",
            serverPublicKey = "q6GQz9IBykkuC3C+kX7l8w7SU9s6yP0Vq8UurgHsiFU=",
            endpoint = "vpn.example.com:51820",
            clientAddress = "10.8.0.2/32",
        )
        val wg = (TunnelProfileParser.parse(wgText) as TunnelParseResult.Valid).profile
        assertNull(VpnGate.connectAttemptText(wg, null))
    }

    @Test
    fun directoryImportedProfilesAreRefusedWithTheDisclosureAgain() {
        val row = VpnGate.parseFeed(FIXTURE_FEED)[0]
        val text = VpnGate.importTextFor(row)
        assertNotNull(text)
        val parsed = TunnelProfileParser.parse(text!!)
        assertTrue(parsed is TunnelParseResult.Valid)
        val profile = (parsed as TunnelParseResult.Valid).profile
        assertTrue(profile is OvpnProfile)
        // Connect attempt: disclosure first, then the named refusal.
        val attempt = VpnGate.connectAttemptText(profile, VpnGate.SOURCE_VPNGATE)
        assertNotNull(attempt)
        assertTrue(attempt!!.startsWith(VpnGate.DISCLOSURE))
        assertTrue(attempt.contains(TunnelProfileParser.OPENVPN_CONNECT_REFUSAL))
    }

    @Test
    fun storeSourceLabelRoundTripsAndImportCarriesTheLabel() {
        // The imported profile keeps its public-server label
        // (the Sphinx name comment rides the OpenVPN text).
        val row = VpnGate.parseFeed(FIXTURE_FEED)[1]
        val parsed = TunnelProfileParser.parse(VpnGate.importTextFor(row)!!)
        val profile = (parsed as TunnelParseResult.Valid).profile
        assertEquals(row.label, profile.name)
        assertEquals("openvpn", profile.protocol)
        val reparsed = TunnelProfileParser.parse(profile.exportText())
        assertEquals(
            row.label,
            (reparsed as TunnelParseResult.Valid).profile.name,
        )

        // The store's source bookkeeping: vpngate for directory
        // imports, nothing for the user's own profiles.
        val sources = mapOf(row.label to VpnGate.SOURCE_VPNGATE)
        val decoded = ProfileSources.decode(ProfileSources.encode(sources))
        assertEquals("vpngate", decoded[row.label])
        assertNull(decoded["Home"])
        assertTrue(ProfileSources.decode(null).isEmpty())
        assertTrue(ProfileSources.decode("garbage line").isEmpty())
        assertFalse(ProfileSources.encode(sources).contains("Home"))
    }
}
