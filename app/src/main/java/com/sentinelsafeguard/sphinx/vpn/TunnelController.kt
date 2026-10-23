package com.sentinelsafeguard.sphinx.vpn

import android.content.Context
import com.sentinelsafeguard.sphinx.core.WgProfile
import com.wireguard.android.backend.GoBackend
import com.wireguard.android.backend.Tunnel
import com.wireguard.config.Config
import com.wireguard.config.InetNetwork
import com.wireguard.config.Interface as WgInterface
import com.wireguard.config.Peer as WgPeer
import com.wireguard.crypto.Key
import com.wireguard.crypto.KeyPair
import java.net.InetAddress

/**
 * The wire between Sphinx and the WireGuard tunnel library
 * (com.wireguard.android:tunnel, Apache-2.0; userspace backend
 * wireguard-go, MIT — see assets/third-party).
 *
 * THE ARCHITECTURAL FACT, stated plainly (TUNNEL-SPEC asks for
 * compromises to be reported, not hidden): the library's
 * [GoBackend] requires its OWN VpnService class
 * (GoBackend.VpnService, declared by the library's manifest
 * and merged into this app) to own the Android VPN interface.
 * Android allows one VPN at a time, so Sphinx's single service
 * cannot simultaneously own that interface for its FILTER
 * packet loop. The arbitration point therefore stays
 * [SphinxVpnService] — it alone decides which mode runs, tears
 * the previous mode down through the ordinary stop path before
 * any tunnel starts, records intent only on successful
 * transitions, and owns the status claims — while the TUNNEL
 * data plane itself is delegated to the library's backend and
 * its service. FILTER/APP_BLOCK shapes never run alongside a
 * tunnel; the modes are exclusive by construction here.
 *
 * The second consequence, also plain: wireguard-go's data
 * plane exposes no packet hook to the Java API, so in
 * TUNNEL+Blocker the DNS gate ([com.sentinelsafeguard.sphinx.core.TunnelDnsGate]
 * / DnsPipeline — implemented and JVM-proven) cannot intercept
 * packets inside the library's TUN. Phase 1 wires TUNNEL+Blocker
 * through this same backend with the profile's DNS servers
 * carried through the tunnel; the packet-level interception of
 * tunnel DNS is the known, named gap, and no copy in the app
 * claims a stronger on-device proof than exists.
 *
 * Kill switch (TUNNEL-SPEC): GoBackend builds its interface
 * with setBlocking(true) — while the backend's service lives
 * and the tunnel is down or handshakeless, packets drop rather
 * than route around the tunnel. "Connected" is claimed only
 * from this controller's fresh-handshake check
 * ([latestHandshakeEpochMs] + TunnelStatusLogic), never from
 * the backend merely being up.
 */
class TunnelController(context: Context) {

    private val appContext = context.applicationContext
    private var backend: GoBackend? = null
    private var tunnel: SphinxTunnel? = null

    class SphinxTunnel(
        private val tunnelName: String,
        private val onChange: (Tunnel.State) -> Unit,
    ) : Tunnel {
        override fun getName(): String = tunnelName
        override fun onStateChange(newState: Tunnel.State) = onChange(newState)
    }

    sealed class ConnectResult {
        object Up : ConnectResult()
        data class Failed(val reason: String) : ConnectResult()
    }

    /**
     * Bring the tunnel up for [profile]. Hostname endpoints are
     * resolved by the backend BEFORE the tunnel engages and
     * the answer pinned for the session (the backend's own
     * discipline: it pre-resolves and refuses on DNS failure) —
     * TUNNEL-SPEC's endpoint rule rides on exactly that.
     * [excludedPackages] bypass the tunnel entirely.
     */
    fun connect(profile: WgProfile, excludedPackages: Set<String>): ConnectResult {
        val privateKey = profile.privateKey
            ?: return ConnectResult.Failed(
                "This profile has no private key, so it cannot connect. " +
                    "Import the full config your provider gave you, or " +
                    "create the profile on this phone so it gets its own keys."
            )
        val config = try {
            buildConfig(profile, privateKey, excludedPackages)
        } catch (e: Exception) {
            return ConnectResult.Failed("This profile could not be prepared: ${e.message}")
        }
        return try {
            val goBackend = backend ?: GoBackend(appContext).also { backend = it }
            val sphinxTunnel = SphinxTunnel(TUNNEL_NAME) {}
            tunnel = sphinxTunnel
            val state = goBackend.setState(sphinxTunnel, Tunnel.State.UP, config)
            if (state == Tunnel.State.UP) {
                ConnectResult.Up
            } else {
                ConnectResult.Failed("The tunnel did not come up.")
            }
        } catch (e: Exception) {
            ConnectResult.Failed("The tunnel could not start: ${e.message}")
        }
    }

    fun disconnect() {
        val goBackend = backend ?: return
        val sphinxTunnel = tunnel ?: return
        try {
            goBackend.setState(sphinxTunnel, Tunnel.State.DOWN, null)
        } catch (e: Exception) {
            // Already down, or the backend's service is gone:
            // the tunnel is down either way, and claiming a
            // finer state than that would be inventing one.
        }
        tunnel = null
    }

    fun isBackendUp(): Boolean {
        val goBackend = backend ?: return false
        val sphinxTunnel = tunnel ?: return false
        return try {
            goBackend.getState(sphinxTunnel) == Tunnel.State.UP
        } catch (e: Exception) {
            false
        }
    }

    /** The backend's latest-handshake report, epoch millis —
     *  the only fact a "connected" claim may rest on. Null when
     *  no peer has ever handshaked (or the backend is down). */
    fun latestHandshakeEpochMs(): Long? {
        val goBackend = backend ?: return null
        val sphinxTunnel = tunnel ?: return null
        return try {
            val stats = goBackend.getStatistics(sphinxTunnel)
            var latest: Long? = null
            for (key in stats.peers()) {
                val peerStats = stats.peer(key) ?: continue
                val stamp = peerStats.latestHandshakeEpochMillis()
                if (stamp > 0 && (latest == null || stamp > latest)) latest = stamp
            }
            latest
        } catch (e: Exception) {
            null
        }
    }

    /** Backend-reported transfer totals (rx, tx) — display
     *  state only, memory-only, per TUNNEL-SPEC's logging
     *  honesty. Zeroes when the backend is down. */
    fun transferTotals(): Pair<Long, Long> {
        val goBackend = backend ?: return 0L to 0L
        val sphinxTunnel = tunnel ?: return 0L to 0L
        return try {
            val stats = goBackend.getStatistics(sphinxTunnel)
            stats.totalRx() to stats.totalTx()
        } catch (e: Exception) {
            0L to 0L
        }
    }

    /**
     * The library [Config] for a profile, built from the
     * profile's structured fields. The profile STORE keeps the
     * complete original text (extras included, lossless); this
     * data-plane config carries every field wireguard-go acts
     * on — keys, addresses, DNS, MTU, per-peer endpoint /
     * allowed-IPs / preshared key / keepalive, and the tunnel
     * exclusions. wg-quick-only directives an import may carry
     * (Table, SaveConfig) are instructions for a shell tool,
     * not for the userspace backend; they stay preserved in
     * the stored text and in every export.
     */
    private fun buildConfig(
        profile: WgProfile,
        privateKey: String,
        excludedPackages: Set<String>,
    ): Config {
        val interfaceBuilder = WgInterface.Builder()
            .setKeyPair(KeyPair(Key.fromBase64(privateKey)))
        for (address in profile.clientAddresses) {
            interfaceBuilder.addAddress(InetNetwork.parse(address))
        }
        for (dns in profile.dnsServers) {
            try {
                interfaceBuilder.addDnsServer(InetAddress.getByName(dns))
            } catch (e: Exception) {
                // A DNS entry the platform cannot use as a
                // server address: the profile's other servers
                // still apply. (Profile DNS names are validated
                // as addresses on the store's paths; a bad one
                // degrades, it does not take the tunnel down.)
            }
        }
        profile.mtu?.let { interfaceBuilder.setMtu(it) }
        if (excludedPackages.isNotEmpty()) {
            interfaceBuilder.excludeApplications(excludedPackages)
        }

        val configBuilder = Config.Builder().setInterface(interfaceBuilder.build())
        for (peer in profile.peers) {
            val peerBuilder = WgPeer.Builder()
                .setPublicKey(Key.fromBase64(peer.publicKey))
            peer.endpoint?.let { peerBuilder.parseEndpoint(it) }
            if (peer.allowedIps.isNotEmpty()) {
                peerBuilder.parseAllowedIPs(peer.allowedIps.joinToString(", "))
            }
            peer.presharedKey?.let { peerBuilder.parsePreSharedKey(it) }
            peer.persistentKeepalive?.let { peerBuilder.setPersistentKeepalive(it) }
            configBuilder.addPeer(peerBuilder.build())
        }
        return configBuilder.build()
    }

    companion object {
        /** The interface name the backend uses. Tunnel names
         *  are constrained by the library (letters/digits and
         *  a few marks, max 15) — the user's profile NAME is a
         *  label and lives in Sphinx's store, not here. */
        const val TUNNEL_NAME = "sphinx"
    }
}
