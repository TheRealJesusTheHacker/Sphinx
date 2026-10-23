package com.sentinelsafeguard.sphinx.core

import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertTrue
import org.junit.Test

/**
 * CONFORMANCE for TUNNEL-SPEC, "The filter questions names; it
 * does not block traffic" — the TUNNEL+Blocker path.
 *
 * Proven here, at JVM level (the deepest level this suite
 * honestly supports — the wireguard-go data plane itself is a
 * native backend and device-only):
 *  - the brain sinkholes a LISTED name in TUNNEL+Blocker;
 *  - an UNLISTED name's DNS is routed to the profile's DNS
 *    servers THROUGH the tunnel, and its non-DNS traffic is
 *    routed to the backend UNTOUCHED — the router has no drop
 *    route for general traffic at all;
 *  - APP_BLOCK's total drop never appears in a tunnel shape:
 *    the arbitration refuses the combination with the trade
 *    stated, instead of inheriting the drop.
 */
class TunnelBlockerConformanceTest {

    private fun lists(): FilterLists = FilterLists(
        Blocklist(listOf("ads.example.com")),
        Allowlist(emptyList()),
    )

    private fun query(name: String, id: Int = 0x2222): ByteArray {
        val out = ArrayList<Byte>()
        fun u16(v: Int) {
            out.add((v shr 8).toByte()); out.add(v.toByte())
        }
        u16(id); u16(0x0100); u16(1); u16(0); u16(0); u16(0)
        for (label in name.split('.')) {
            out.add(label.length.toByte())
            label.forEach { out.add(it.code.toByte()) }
        }
        out.add(0); u16(1); u16(1)
        return out.toByteArray()
    }

    @Test
    fun tunnelBlockerSinkholesListedNameWhileUnlistedTrafficPassesToBackend() {
        val gate = TunnelDnsGate(lists())

        // Listed name: the brain sinkholes it — decided locally,
        // the forwarder (the tunnel's DNS path) is never asked.
        assertEquals(
            TunnelPacketRouter.Route.SINKHOLE_DNS,
            TunnelPacketRouter.route(isDnsQuery = true, dnsName = "ads.example.com", gate = gate),
        )
        var forwardCalls = 0
        val pipeline = DnsPipeline(lists()) { q ->
            forwardCalls++
            // The fake "through the tunnel" answer: the query
            // echoed back with response bits set.
            val r = q.copyOf()
            r[2] = (r[2].toInt() or 0x80).toByte()
            r
        }
        val listed = pipeline.processQuery(query("ads.example.com"))
        assertTrue(listed is DnsPipeline.Result.Sinkholed)
        assertEquals(0, forwardCalls)

        // Unlisted name: its DNS forwards through the tunnel to
        // the profile's servers, and it resolves.
        assertEquals(
            TunnelPacketRouter.Route.FORWARD_DNS_THROUGH_TUNNEL,
            TunnelPacketRouter.route(
                isDnsQuery = true, dnsName = "news.example.org", gate = gate,
            ),
        )
        val unlisted = pipeline.processQuery(query("news.example.org"))
        assertTrue(unlisted is DnsPipeline.Result.Forwarded)
        assertEquals(1, forwardCalls)

        // Unlisted name's general (non-DNS) traffic: to the
        // backend, untouched — in TUNNEL+Blocker and in
        // TUNNEL-only alike. There is no other honest route.
        assertEquals(
            TunnelPacketRouter.Route.TO_BACKEND_UNTOUCHED,
            TunnelPacketRouter.route(isDnsQuery = false, dnsName = null, gate = gate),
        )
        assertEquals(
            TunnelPacketRouter.Route.TO_BACKEND_UNTOUCHED,
            TunnelPacketRouter.route(isDnsQuery = false, dnsName = null, gate = null),
        )
        // TUNNEL-only DNS is unfiltered by design: every query
        // forwards, listed or not — the UI says ads are not
        // blocked in that mode.
        assertEquals(
            TunnelPacketRouter.Route.FORWARD_DNS_THROUGH_TUNNEL,
            TunnelPacketRouter.route(isDnsQuery = true, dnsName = "ads.example.com", gate = null),
        )
    }

    @Test
    fun appBlockDropIsQuarantinedOutOfTunnelShapes() {
        // The router's whole vocabulary: no drop route exists
        // for a tunnel shape to inherit.
        assertEquals(
            setOf(
                TunnelPacketRouter.Route.TO_BACKEND_UNTOUCHED,
                TunnelPacketRouter.Route.SINKHOLE_DNS,
                TunnelPacketRouter.Route.FORWARD_DNS_THROUGH_TUNNEL,
            ),
            TunnelPacketRouter.Route.values().toSet(),
        )
        // Offering blocked-app rules and a tunnel together is
        // refused with the trade stated — never silently merged.
        val refused = TunnelArbitration.tunnelRequest(setOf("com.example.game"), withBlocker = true)
        assertTrue(refused is TunnelArbitration.Decision.Refused)
        assertEquals(
            TunnelArbitration.APP_BLOCK_TRADE_REFUSAL,
            (refused as TunnelArbitration.Decision.Refused).reason,
        )
        // And the blocker arbitration stays its own shape.
        assertEquals(
            SphinxMode.APP_BLOCK,
            TunnelArbitration.blockerMode(setOf("com.example.game")),
        )
        assertFalse(
            TunnelArbitration.tunnelRequest(emptySet(), withBlocker = false)
                is TunnelArbitration.Decision.Refused,
        )
    }
}
