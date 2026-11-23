package com.nexlink.app

import com.nexlink.app.data.local.SyncEvent
import org.junit.Assert.assertEquals
import org.junit.Assert.assertNotEquals
import org.junit.Assert.assertTrue
import org.junit.Test

class SyncEventTest {

    @Test
    fun defaultsInitializePendingEventWithZeroIdAndRetries() {
        val before = System.currentTimeMillis()
        val event = SyncEvent(
            type = "notification",
            payload = "{\"packageName\":\"com.example.chat\",\"title\":\"Hi\"}"
        )
        val after = System.currentTimeMillis()

        assertEquals(0L, event.id)
        assertEquals("PENDING", event.status)
        assertEquals(0, event.retryCount)
        assertEquals("notification", event.type)
        assertTrue(event.createdAt in before..after)
    }

    @Test
    fun copyPreservesIdentityAndAllowsLifecycleProgression() {
        val pending = SyncEvent(
            id = 42L,
            type = "notification",
            payload = "{\"id\":42}",
            createdAt = 1_700_000_000_000L,
            status = "PENDING",
            retryCount = 0
        )

        val inProgress = pending.copy(status = "IN_PROGRESS", retryCount = 1)
        val synced = inProgress.copy(status = "SYNCED")

        assertEquals("PENDING", pending.status)
        assertEquals(0, pending.retryCount)
        assertEquals("IN_PROGRESS", inProgress.status)
        assertEquals(1, inProgress.retryCount)
        assertEquals("SYNCED", synced.status)
        assertEquals(42L, synced.id)
        assertEquals(pending.payload, synced.payload)
        assertNotEquals(pending, synced)
    }
}
