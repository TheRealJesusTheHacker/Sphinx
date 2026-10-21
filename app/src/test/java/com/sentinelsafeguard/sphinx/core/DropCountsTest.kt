package com.sentinelsafeguard.sphinx.core

import org.junit.Assert.assertEquals
import org.junit.Assert.assertTrue
import org.junit.Test

class DropCountsTest {

    @Test
    fun countsPerAppAndInTotal() {
        val drops = DropCounts()
        drops.increment("com.example.game")
        drops.increment("com.example.game")
        drops.increment("com.example.ads")
        assertEquals(2L, drops.countFor("com.example.game"))
        assertEquals(1L, drops.countFor("com.example.ads"))
        assertEquals(0L, drops.countFor("com.example.never"))
        assertEquals(3L, drops.total())
    }

    @Test
    fun unknownOwnersLandInTheUnattributedBucket() {
        val drops = DropCounts()
        drops.increment(null)
        assertEquals(1L, drops.countFor(DropCounts.UNATTRIBUTED))
        assertEquals(1L, drops.total())
    }

    @Test
    fun snapshotIsACopy() {
        val drops = DropCounts()
        drops.increment("com.example.game")
        val snapshot = drops.snapshot()
        drops.increment("com.example.game")
        assertEquals(1L, snapshot["com.example.game"])
        assertEquals(2L, drops.countFor("com.example.game"))
    }

    @Test
    fun clearEmptiesEverything() {
        val drops = DropCounts()
        drops.increment("com.example.game")
        drops.increment(null)
        drops.clear()
        assertEquals(0L, drops.total())
        assertTrue(drops.snapshot().isEmpty())
    }
}
