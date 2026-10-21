package com.sentinelsafeguard.sphinx.core

/**
 * Packets dropped per blocked app, while the Android edition runs in
 * its app-block capture mode (docs/FILTER-SPEC.md, "Per-app rules").
 *
 * Same privacy rules as the query log and the counters: this lives
 * only in memory on the device, is never written to disk by the core,
 * and is never transmitted anywhere. It exists so the user can see
 * that a blocked app really is being stopped — and how often it keeps
 * trying.
 *
 * Pure Kotlin — no Android APIs. Shared by every Sphinx edition.
 */
class DropCounts {

    private val counts = HashMap<String, Long>()

    /** Record one dropped packet for [packageName]. A null name —
     *  the packet's owner couldn't be identified — lands in the
     *  [UNATTRIBUTED] bucket rather than being lost or guessed at. */
    @Synchronized
    fun increment(packageName: String?) {
        val key = packageName ?: UNATTRIBUTED
        counts[key] = (counts[key] ?: 0L) + 1L
    }

    @Synchronized
    fun countFor(packageName: String): Long = counts[packageName] ?: 0L

    /** Every dropped packet, attributed and not. */
    @Synchronized
    fun total(): Long = counts.values.sum()

    /** A copy of the per-app counts — callers can't mutate the
     *  counters through it. */
    @Synchronized
    fun snapshot(): Map<String, Long> = counts.toMap()

    @Synchronized
    fun clear() {
        counts.clear()
    }

    companion object {
        /** Bucket key for packets whose owning app is unknown. */
        const val UNATTRIBUTED = "<unattributed>"
    }
}
