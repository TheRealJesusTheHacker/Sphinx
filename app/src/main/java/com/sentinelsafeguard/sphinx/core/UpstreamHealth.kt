package com.sentinelsafeguard.sphinx.core

import java.net.InetAddress

/**
 * The forwarder's per-resolver memory for the diagnostics screen
 * (fix2 hunt, 2026-10-23): what happened the last time each
 * upstream in the chain was tried, and which chain is in use.
 *
 * Memory-only, like the query log: outcomes and resolver
 * addresses, never query contents. Pure Kotlin — no Android
 * APIs — so the recording discipline is JVM-testable; the VPN
 * service feeds it through [DnsForwarder]'s outcome callback
 * and owns the chain snapshots (it is the only component that
 * can read the platform's networks).
 */
object UpstreamHealth {

    /** What one upstream attempt ended in. */
    enum class Outcome {
        /** The resolver answered and its answer was delivered. */
        ANSWERED,

        /** No matching answer arrived inside the attempt's budget
         *  (or the socket failed trying). */
        TIMED_OUT_OR_ERROR,

        /** The platform refused to protect the forwarding socket;
         *  nothing was sent on it (the SEV-1 discipline). */
        PROTECT_REFUSED,

        /** Binding the socket to the resolver's own network was
         *  refused; nothing was sent on it. */
        BIND_REFUSED,
    }

    data class Record(
        val outcome: Outcome,
        val atMillis: Long,
        /** Round-trip of the successful attempt; -1 otherwise. */
        val rttMillis: Long,
    )

    /** One entry of the chain in use, in the order it is tried
     *  before last-responder affinity reorders it per query. */
    data class ChainEntry(
        val address: InetAddress,
        /** "Phone's own DNS" (captured) or "Public" — where this
         *  resolver came from. */
        val fromPhone: Boolean,
        /** Scope note for the diagnostics screen: "global",
         *  "link-local (this network only)", "private (ULA)", … */
        val scopeNote: String,
    )

    private val records = HashMap<String, Record>()

    /** The chain the service most recently handed the forwarder,
     *  in chain order. Empty until the filter first forwards. */
    @Volatile
    var chainInUse: List<ChainEntry> = emptyList()

    /** True when the most recent system-DNS capture found no
     *  usable phone DNS servers at all — the chain has no floor.
     *  A first-class state the diagnostics screen states plainly,
     *  never a silent gap (fix2 hunt finding F2). */
    @Volatile
    var floorMissing: Boolean = false

    @Synchronized
    fun record(resolver: InetAddress, outcome: Outcome, atMillis: Long, rttMillis: Long = -1) {
        records[key(resolver)] = Record(outcome, atMillis, rttMillis)
    }

    @Synchronized
    fun lastOutcome(resolver: InetAddress): Record? = records[key(resolver)]

    /** Test hook: health is process-wide, so tests reset it. */
    @Synchronized
    internal fun reset() {
        records.clear()
        chainInUse = emptyList()
        floorMissing = false
    }

    private fun key(resolver: InetAddress): String =
        resolver.address.joinToString(".") { (it.toInt() and 0xFF).toString() }
}

/**
 * Validation and classification of the DNS servers the platform
 * reports for the phone's own networks (fix2 hunt finding F2).
 *
 * The SEV-1 chain trusted the capture blindly. On a DNS64/NAT64
 * or link-local-heavy carrier the capture can contain addresses
 * a forwarding socket can never use as-is — the unspecified
 * address, a loopback, Sphinx's own virtual servers — and every
 * such entry costs a full attempt timeout on the walk toward
 * the floor, or worse, poses as a floor that is not there.
 * Entries that cannot be used at all are dropped here, in the
 * pure core where the discipline is testable; entries that are
 * usable only on their own network (link-local, scoped) are
 * kept and flagged, and the service binds their sockets to the
 * network they came from.
 */
object SystemDnsFilter {

    /** Sphinx's own virtual DNS addresses — a capture naming one
     *  of these is reading the filter itself, not the phone. */
    private val SELF_V4 = byteArrayOf(10, 10, 10, 10)
    private val SELF_V6 = byteArrayOf(
        0xFD.toByte(), 0x00, 0x00, 0x10, 0x00, 0x10, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x10,
    )

    /** True when [address] can never be an upstream: unspecified,
     *  loopback, multicast, or one of Sphinx's own virtual DNS
     *  addresses. */
    fun isUnusable(address: InetAddress): Boolean {
        if (address.isAnyLocalAddress || address.isLoopbackAddress ||
            address.isMulticastAddress
        ) {
            return true
        }
        val raw = address.address
        return raw.contentEquals(SELF_V4) || raw.contentEquals(SELF_V6)
    }

    /** Plain-language scope of an address, for diagnostics. */
    fun scopeNote(address: InetAddress): String = when {
        address.isLinkLocalAddress -> "link-local (this network only)"
        isUniqueLocal(address) -> "private IPv6 (ULA)"
        address.isSiteLocalAddress -> "private address"
        address.address.size == 16 && isNat64WellKnown(address) ->
            "NAT64 translated (carrier IPv6 network)"
        address.address.size == 16 -> "IPv6"
        else -> "IPv4"
    }

    /** Unique-local IPv6 (fc00::/7): carrier DNS64 synthesizers
     *  and router DNS commonly live here. */
    private fun isUniqueLocal(address: InetAddress): Boolean {
        val raw = address.address
        return raw.size == 16 && (raw[0].toInt() and 0xFE) == 0xFC
    }

    /** The NAT64 well-known prefix 64:ff9b::/96: an address inside
     *  it is an IPv4 resolver seen through the carrier's translator. */
    private fun isNat64WellKnown(address: InetAddress): Boolean {
        val raw = address.address
        if (raw.size != 16) return false
        val prefix = byteArrayOf(0x00, 0x64, 0xFF.toByte(), 0x9B.toByte())
        return raw.copyOfRange(0, 4).contentEquals(prefix) &&
            raw.copyOfRange(4, 12).all { it.toInt() == 0 }
    }

    /** The usable capture, order preserved, duplicates removed. */
    fun usable(captured: List<InetAddress>): List<InetAddress> =
        captured.filter { !isUnusable(it) }.distinct()
}
