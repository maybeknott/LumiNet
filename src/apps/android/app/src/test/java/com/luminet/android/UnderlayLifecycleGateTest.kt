package com.luminet.android

import org.junit.Assert.assertFalse
import org.junit.Assert.assertNotEquals
import org.junit.Assert.assertTrue
import org.junit.Test

class UnderlayLifecycleGateTest {
    @Test
    fun stopInvalidatesCallbacksFromThePreviousGeneration() {
        val gate = UnderlayLifecycleGate()
        val callbackGeneration = gate.start()

        assertTrue(gate.isCurrent(callbackGeneration))
        gate.stop()

        assertFalse(gate.isCurrent(callbackGeneration))
    }

    @Test
    fun restartDoesNotRevalidateAStaleCallback() {
        val gate = UnderlayLifecycleGate()
        val staleGeneration = gate.start()
        gate.stop()
        val currentGeneration = gate.start()

        assertNotEquals(staleGeneration, currentGeneration)
        assertFalse(gate.isCurrent(staleGeneration))
        assertTrue(gate.isCurrent(currentGeneration))
    }
}
