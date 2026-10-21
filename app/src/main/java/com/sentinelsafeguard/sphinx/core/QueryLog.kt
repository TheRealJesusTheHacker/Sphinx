package com.sentinelsafeguard.sphinx.core

/**
 * A short, on-device record of recent DNS queries: what was asked, and
 * whether Sphinx blocked it.
 *
 * Privacy rules (docs/FILTER-SPEC.md, honesty rules):
 *  - The log lives only in memory on the device. It is never written to
 *    disk by the core, never transmitted anywhere, and it is gone when
 *    the process dies.
 *  - It is a ring buffer with a hard cap, so it can never grow without
 *    bound: once full, each new entry pushes out the oldest.
 *
 * Pure Kotlin — no Android APIs. Shared by every Sphinx edition.
 */
class QueryLog(private val capacity: Int = DEFAULT_CAPACITY) {

    data class Entry(
        val name: String,
        val blocked: Boolean,
        val timestampMillis: Long,
    )

    private val entries = ArrayDeque<Entry>()

    init {
        require(capacity > 0) { "query log capacity must be positive" }
    }

    @Synchronized
    fun record(name: String, blocked: Boolean, timestampMillis: Long) {
        if (entries.size >= capacity) entries.removeFirst()
        entries.addLast(Entry(name, blocked, timestampMillis))
    }

    /** Newest first. A copy — callers can't mutate the log through it. */
    @Synchronized
    fun snapshot(): List<Entry> = entries.reversed()

    @Synchronized
    fun clear() {
        entries.clear()
    }

    val size: Int
        @Synchronized get() = entries.size

    companion object {
        const val DEFAULT_CAPACITY = 500
    }
}
