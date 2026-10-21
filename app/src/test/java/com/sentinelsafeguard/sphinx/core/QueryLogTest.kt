package com.sentinelsafeguard.sphinx.core

import org.junit.Assert.assertEquals
import org.junit.Assert.assertTrue
import org.junit.Test

class QueryLogTest {

    @Test
    fun recordsNewestFirst() {
        val log = QueryLog(capacity = 10)
        log.record("a.example.com", blocked = true, timestampMillis = 1)
        log.record("b.example.com", blocked = false, timestampMillis = 2)
        val snap = log.snapshot()
        assertEquals(2, snap.size)
        assertEquals("b.example.com", snap[0].name)
        assertEquals(false, snap[0].blocked)
        assertEquals(2L, snap[0].timestampMillis)
        assertEquals("a.example.com", snap[1].name)
        assertEquals(true, snap[1].blocked)
    }

    @Test
    fun ringBufferCapsAndDropsOldest() {
        val log = QueryLog(capacity = 3)
        for (i in 1..5) {
            log.record("host$i.example.com", blocked = i % 2 == 0, timestampMillis = i.toLong())
        }
        assertEquals(3, log.size)
        val names = log.snapshot().map { it.name }
        assertEquals(
            listOf("host5.example.com", "host4.example.com", "host3.example.com"),
            names,
        )
    }

    @Test
    fun clearEmptiesTheLog() {
        val log = QueryLog(capacity = 10)
        log.record("a.example.com", blocked = true, timestampMillis = 1)
        log.clear()
        assertEquals(0, log.size)
        assertTrue(log.snapshot().isEmpty())
    }

    @Test
    fun defaultCapacityIsBounded() {
        val log = QueryLog()
        repeat(QueryLog.DEFAULT_CAPACITY + 50) {
            log.record("h$it.example.com", blocked = false, timestampMillis = it.toLong())
        }
        assertEquals(QueryLog.DEFAULT_CAPACITY, log.size)
    }

    @Test
    fun snapshotIsACopy() {
        val log = QueryLog(capacity = 10)
        log.record("a.example.com", blocked = true, timestampMillis = 1)
        val snap = log.snapshot()
        log.record("b.example.com", blocked = false, timestampMillis = 2)
        assertEquals(1, snap.size)
        assertEquals(2, log.size)
    }
}
