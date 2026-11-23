package com.nexlink.app

import org.junit.Assert.assertEquals
import org.junit.Assert.assertNotEquals
import org.junit.Assert.assertTrue
import org.junit.Test

class ConnectionServiceConstantsTest {

    @Test
    fun connectionServiceActionsMatchExpectedNamespaceContract() {
        assertEquals("com.nexlink.app.START_CONNECTION", ConnectionService.ACTION_START)
        assertEquals("com.nexlink.app.STOP_CONNECTION", ConnectionService.ACTION_STOP)
        assertNotEquals(ConnectionService.ACTION_START, ConnectionService.ACTION_STOP)
        assertTrue(ConnectionService.ACTION_START.startsWith("com.nexlink.app."))
        assertTrue(ConnectionService.ACTION_STOP.startsWith("com.nexlink.app."))
    }
}
