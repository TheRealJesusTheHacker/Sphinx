package com.sentinelsafeguard.sphinx.core

/**
 * The TUNNEL mode model — docs/TUNNEL-SPEC.md, "The mode model"
 * and "The filter questions names; it does not block traffic".
 *
 * Four populations now exist on Android: FILTER and APP_BLOCK
 * (FILTER-SPEC, unchanged), plus the TUNNEL shapes this file
 * arbitrates. The owner's standing criterion governs all of
 * them: the filter's ONLY action is the DNS decision — a listed
 * name gets the sinkhole answer, fast; every unlisted name
 * resolves normally and its traffic passes untouched, including
 * names that merely look tracker-adjacent. In TUNNEL shapes,
 * non-DNS packets go to the tunnel backend, period. The only
 * blocking beyond DNS decisions in a tunnel mode is the
 * kill-switch state on tunnel failure — announced, with the
 * one-tap intentional disconnect. APP_BLOCK's total drop stays
 * quarantined to APP_BLOCK: it is never a TUNNEL default and
 * no mode transition inherits it.
 *
 * Pure Kotlin — no Android APIs.
 */
enum class SphinxMode {
    OFF,
    FILTER,
    APP_BLOCK,
    TUNNEL,
    TUNNEL_BLOCKER,
}

object TunnelArbitration {

    /** The refusal stated when app-block rules and a TUNNEL
     *  shape are offered together (TUNNEL-SPEC, Android
     *  population honesty): the trade is stated, not hidden. */
    const val APP_BLOCK_TRADE_REFUSAL: String =
        "An app blocked outright can't be blocked inside a VPN " +
            "tunnel: blocking drops all of an app's traffic, and a " +
            "tunnel's job is to carry traffic to your server. Clear " +
            "the blocked-app rules first, or stay in blocker mode — " +
            "Sphinx won't quietly do one while saying the other."

    sealed class Decision {
        data class Allowed(val mode: SphinxMode) : Decision()
        data class Refused(val reason: String) : Decision()
    }

    /**
     * May a TUNNEL shape start while these app rules stand?
     * Blocked-outright rules refuse the tunnel with the trade
     * stated. Excluded (never-filtered) rules are FILTER-mode
     * rules; TUNNEL has its own exclusion set (the tunnel
     * picker), and FILTER exclusions do not leak into it.
     */
    fun tunnelRequest(blockedPackages: Set<String>, withBlocker: Boolean): Decision =
        if (blockedPackages.isNotEmpty()) {
            Decision.Refused(APP_BLOCK_TRADE_REFUSAL)
        } else {
            Decision.Allowed(if (withBlocker) SphinxMode.TUNNEL_BLOCKER else SphinxMode.TUNNEL)
        }

    /** The existing FILTER-SPEC arbitration, restated so mode
     *  decisions live in one place: any blocked app means the
     *  APP_BLOCK shape; otherwise the FILTER shape. A TUNNEL
     *  request never consults this — the shapes do not blend. */
    fun blockerMode(blockedPackages: Set<String>): SphinxMode =
        if (blockedPackages.isEmpty()) SphinxMode.FILTER else SphinxMode.APP_BLOCK

    /**
     * Disconnecting a tunnel returns to the mode the user had
     * before VPN (TUNNEL-SPEC): Blocker only, or Off — through
     * the ordinary stop path. Anything else stored as "before"
     * (a stale TUNNEL record, an APP_BLOCK the rules no longer
     * support) resolves to Off rather than inventing a mode.
     */
    fun disconnectReturnsTo(preVpnMode: SphinxMode?): SphinxMode =
        if (preVpnMode == SphinxMode.FILTER) SphinxMode.FILTER else SphinxMode.OFF

    /** One tunnel at a time: connecting a second profile first
     *  disconnects the first through the ordinary stop path.
     *  This is that sequencing, as a decision the service acts
     *  on — there is no overlap state. */
    fun connectSequence(activeProfile: String?, requestedProfile: String): List<String> =
        if (activeProfile != null && activeProfile != requestedProfile) {
            listOf("disconnect:$activeProfile", "connect:$requestedProfile")
        } else {
            listOf("connect:$requestedProfile")
        }
}

/**
 * When a tunnel may call itself "connected" — and when the
 * kill switch is the honest status instead (TUNNEL-SPEC,
 * "Kill-switch semantics"). Connected comes ONLY from the
 * backend's fresh handshake statistics: never from intent,
 * never from configuration, never from a process running.
 */
object TunnelStatusLogic {

    /** A handshake younger than this is fresh. WireGuard
     *  re-handshakes roughly every two minutes under traffic;
     *  three minutes is the freshness window the status claims
     *  are allowed to lean on. */
    const val HANDSHAKE_FRESH_MS: Long = 180_000L

    fun isConnectedFresh(
        backendUp: Boolean,
        lastHandshakeEpochMs: Long?,
        nowEpochMs: Long,
    ): Boolean {
        if (!backendUp) return false
        val handshake = lastHandshakeEpochMs ?: return false
        if (handshake <= 0L) return false
        val age = nowEpochMs - handshake
        return age in 0..HANDSHAKE_FRESH_MS
    }

    /**
     * The kill-switch state: VPN intent is armed, but there is
     * no fresh handshake — covered traffic blocks (it does not
     * fall back to the direct route) and the status must say so
     * in plain language with the two visible choices. This is
     * the ONLY full-block state a tunnel mode may be in, and it
     * is never silent.
     */
    fun killSwitchBlocking(
        intentArmed: Boolean,
        backendUp: Boolean,
        lastHandshakeEpochMs: Long?,
        nowEpochMs: Long,
    ): Boolean =
        intentArmed && !isConnectedFresh(backendUp, lastHandshakeEpochMs, nowEpochMs)

    const val KILL_SWITCH_TEXT: String =
        "VPN disconnected — traffic is blocked, not going around the tunnel"
}

/**
 * The DNS brain gate for TUNNEL+Blocker: the same FILTER-SPEC
 * decision the blocker modes make (allowlist wins, blocklist
 * decides), named for the tunnel path. This gate decides; it
 * does not forward anything itself — forwarding is the shared
 * [DnsForwarder]'s job, inherited, never forked.
 */
class TunnelDnsGate(private val lists: FilterLists) {
    enum class Decision { SINKHOLE, FORWARD }

    fun decide(name: String): Decision =
        if (lists.isBlocked(name)) Decision.SINKHOLE else Decision.FORWARD

    fun isBlocked(name: String): Boolean = lists.isBlocked(name)
}

/**
 * Where one packet goes in a TUNNEL shape. The routing table
 * is the owner's criterion in code:
 *  - a non-DNS packet goes to the backend, untouched — always;
 *  - a DNS query for a listed name is sinkholed by the brain;
 *  - a DNS query for an unlisted name is forwarded to the
 *    profile's DNS servers THROUGH the tunnel (in TUNNEL-only
 *    mode, unfiltered: the gate is absent and every query
 *    forwards).
 * There is no fourth route. In particular there is no drop
 * route for general traffic in a tunnel shape.
 */
object TunnelPacketRouter {
    enum class Route { TO_BACKEND_UNTOUCHED, SINKHOLE_DNS, FORWARD_DNS_THROUGH_TUNNEL }

    fun route(
        isDnsQuery: Boolean,
        dnsName: String?,
        gate: TunnelDnsGate?,
    ): Route {
        if (!isDnsQuery) return Route.TO_BACKEND_UNTOUCHED
        if (gate == null) return Route.FORWARD_DNS_THROUGH_TUNNEL
        return if (dnsName != null && gate.decide(dnsName) == TunnelDnsGate.Decision.SINKHOLE) {
            Route.SINKHOLE_DNS
        } else {
            Route.FORWARD_DNS_THROUGH_TUNNEL
        }
    }
}

/**
 * The DNS decision pipeline both blocker paths share: parse,
 * decide, and either sinkhole at once or forward through the
 * caller's forwarding function. Blocked names never touch the
 * forwarder — the sinkhole is built locally and returned
 * immediately, so a refusal is never a timeout by another
 * name. Unlisted names go to the forwarder (in production the
 * shared [DnsForwarder] with its full fallback discipline);
 * a forwarder that comes back empty-handed yields
 * [Result.Unanswered] — the asking app retries, per
 * FILTER-SPEC — and nothing in here invents an answer.
 *
 * The service supplies [forward]; tests supply fakes in the
 * ForwarderTest pattern.
 */
class DnsPipeline(
    private val lists: FilterLists,
    private val forward: (ByteArray) -> ByteArray?,
) {
    sealed class Result {
        abstract val name: String?
        abstract val blocked: Boolean

        /** Listed name: answered locally with the sinkhole. */
        data class Sinkholed(
            override val name: String,
            val response: ByteArray,
        ) : Result() {
            override val blocked: Boolean get() = true
        }

        /** Unlisted name: the forwarder's real answer. */
        data class Forwarded(
            override val name: String,
            val response: ByteArray,
        ) : Result() {
            override val blocked: Boolean get() = false
        }

        /** Unlisted name the forwarder could not answer, or a
         *  packet that is not a question at all. */
        data class Unanswered(
            override val name: String?,
            override val blocked: Boolean = false,
        ) : Result()
    }

    fun processQuery(queryBytes: ByteArray): Result {
        val dns = DnsPacket.parse(queryBytes, queryBytes.size)
            ?: return Result.Unanswered(null)
        if (dns.isResponse) return Result.Unanswered(null)
        if (lists.isBlocked(dns.questionName)) {
            return Result.Sinkholed(dns.questionName, dns.buildSinkholeResponse())
        }
        val answer = forward(queryBytes)
        return if (answer != null) {
            Result.Forwarded(dns.questionName, answer)
        } else {
            Result.Unanswered(dns.questionName)
        }
    }
}
