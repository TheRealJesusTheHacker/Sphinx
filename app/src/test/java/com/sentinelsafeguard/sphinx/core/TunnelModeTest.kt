package com.sentinelsafeguard.sphinx.core

import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertTrue
import org.junit.Test

/**
 * The TUNNEL mode model: arbitration, the connected rule, the
 * kill-switch state, on-device profile construction, the
 * OpenVPN Phase 1 refusal, and the QR round-trip of the same
 * config text (no second format).
 */
class TunnelModeTest {

    private val now = 1_700_000_000_000L

    @Test
    fun tunnelRequestsAreAllowedOnlyWithoutBlockedApps() {
        assertEquals(
            TunnelArbitration.Decision.Allowed(SphinxMode.TUNNEL),
            TunnelArbitration.tunnelRequest(emptySet(), withBlocker = false),
        )
        assertEquals(
            TunnelArbitration.Decision.Allowed(SphinxMode.TUNNEL_BLOCKER),
            TunnelArbitration.tunnelRequest(emptySet(), withBlocker = true),
        )
        // Excluded (never-filtered) FILTER rules do not block a
        // tunnel; TUNNEL has its own exclusion set.
        assertTrue(
            TunnelArbitration.tunnelRequest(emptySet(), withBlocker = true)
                is TunnelArbitration.Decision.Allowed,
        )
    }

    @Test
    fun disconnectReturnsToThePreVpnMode() {
        assertEquals(
            SphinxMode.FILTER,
            TunnelArbitration.disconnectReturnsTo(SphinxMode.FILTER),
        )
        assertEquals(
            SphinxMode.OFF,
            TunnelArbitration.disconnectReturnsTo(SphinxMode.OFF),
        )
        assertEquals(
            SphinxMode.OFF,
            TunnelArbitration.disconnectReturnsTo(SphinxMode.TUNNEL),
        )
        assertEquals(SphinxMode.OFF, TunnelArbitration.disconnectReturnsTo(null))
    }

    @Test
    fun oneTunnelAtATimeDisconnectsTheFirst() {
        assertEquals(
            listOf("disconnect:Home", "connect:Office"),
            TunnelArbitration.connectSequence("Home", "Office"),
        )
        assertEquals(
            listOf("connect:Office"),
            TunnelArbitration.connectSequence(null, "Office"),
        )
        assertEquals(
            listOf("connect:Home"),
            TunnelArbitration.connectSequence("Home", "Home"),
        )
    }

    @Test
    fun connectedComesOnlyFromAFreshHandshake() {
        assertTrue(
            TunnelStatusLogic.isConnectedFresh(
                backendUp = true,
                lastHandshakeEpochMs = now - 60_000L,
                nowEpochMs = now,
            ),
        )
        // Stale handshake: not connected, however the intent reads.
        assertFalse(
            TunnelStatusLogic.isConnectedFresh(
                backendUp = true,
                lastHandshakeEpochMs = now - TunnelStatusLogic.HANDSHAKE_FRESH_MS - 1,
                nowEpochMs = now,
            ),
        )
        // No handshake ever: not connected.
        assertFalse(
            TunnelStatusLogic.isConnectedFresh(true, null, now),
        )
        assertFalse(
            TunnelStatusLogic.isConnectedFresh(true, 0L, now),
        )
        // Backend down: not connected even with a fresh stamp.
        assertFalse(
            TunnelStatusLogic.isConnectedFresh(false, now - 1_000L, now),
        )
    }

    @Test
    fun killSwitchBlocksOnlyWhileIntentIsArmedAndUnproven() {
        assertTrue(
            TunnelStatusLogic.killSwitchBlocking(
                intentArmed = true, backendUp = false,
                lastHandshakeEpochMs = null, nowEpochMs = now,
            ),
        )
        assertTrue(
            TunnelStatusLogic.killSwitchBlocking(
                intentArmed = true, backendUp = true,
                lastHandshakeEpochMs = now - 999_999L, nowEpochMs = now,
            ),
        )
        assertFalse(
            TunnelStatusLogic.killSwitchBlocking(
                intentArmed = true, backendUp = true,
                lastHandshakeEpochMs = now - 5_000L, nowEpochMs = now,
            ),
        )
        // No intent: nothing is armed, so nothing claims to block.
        assertFalse(
            TunnelStatusLogic.killSwitchBlocking(
                intentArmed = false, backendUp = false,
                lastHandshakeEpochMs = null, nowEpochMs = now,
            ),
        )
    }

    @Test
    fun locallyBuiltProfileParsesAndRoundTrips() {
        // Corpus example keys only — never real key material.
        val text = TunnelProfileParser.buildLocalConfigText(
            name = "My Server",
            privateKey = "hI9byVWLK8639iOPJ8Z3ej9sp4rhqOdnHQ3pfp0N35s=",
            serverPublicKey = "q6GQz9IBykkuC3C+kX7l8w7SU9s6yP0Vq8UurgHsiFU=",
            endpoint = "vpn.example.com:51820",
            clientAddress = "10.8.0.2/32",
            dnsServers = listOf("10.8.0.1"),
        )
        val result = TunnelProfileParser.parse(text)
        assertTrue(result is TunnelParseResult.Valid)
        val profile = (result as TunnelParseResult.Valid).profile as WgProfile
        assertEquals("My Server", profile.name)
        assertEquals("all", profile.scope)
        assertEquals(text, profile.exportText())
    }

    @Test
    fun openVpnProfileIsStoredAndConnectIsRefusedWithTheReason() {
        val text = "client\ndev tun\nproto udp\nremote vpn-node.example.org 1194\n" +
            "resolv-retry infinite\nnobind\npersist-key\npersist-tun\n"
        val result = TunnelProfileParser.parse(text)
        assertTrue(result is TunnelParseResult.Valid)
        val profile = (result as TunnelParseResult.Valid).profile
        assertEquals("openvpn", profile.protocol)
        assertEquals("vpn-node.example.org:1194", profile.endpoint)
        assertEquals(text, profile.exportText())
        // The Phase 1 connect refusal names the reason (the
        // licensing gate), in plain words.
        assertTrue(TunnelProfileParser.OPENVPN_CONNECT_REFUSAL.contains("refused"))
        assertTrue(TunnelProfileParser.OPENVPN_CONNECT_REFUSAL.contains("MIT"))
    }

    @Test
    fun qrRoundTripCarriesTheSameConfigText() {
        val text = TunnelProfileParser.buildLocalConfigText(
            name = "QR Home",
            privateKey = "hI9byVWLK8639iOPJ8Z3ej9sp4rhqOdnHQ3pfp0N35s=",
            serverPublicKey = "q6GQz9IBykkuC3C+kX7l8w7SU9s6yP0Vq8UurgHsiFU=",
            endpoint = "vpn.example.com:51820",
            clientAddress = "10.8.0.2/32",
        )
        val matrix = TunnelQr.encode(text)
        assertTrue(matrix != null)
        val gray = TunnelQr.renderGray(matrix!!)
        val decoded = TunnelQr.decodeGray(gray, matrix.width, matrix.height)
        assertEquals(text, decoded)
        // And what a QR carries parses through the same front door.
        assertTrue(TunnelProfileParser.parse(decoded!!) is TunnelParseResult.Valid)
    }
}
