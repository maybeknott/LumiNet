package com.luminet.android

import androidx.test.ext.junit.runners.AndroidJUnit4
import androidx.test.platform.app.InstrumentationRegistry
import org.junit.Assert.assertFalse
import org.junit.Assert.assertTrue
import org.junit.Test
import org.junit.runner.RunWith

@RunWith(AndroidJUnit4::class)
class UnderlayLifecycleInstrumentedTest {
    @Test
    fun staleGenerationCannotBecomeCurrentAfterStopOrRestart() {
        val context = InstrumentationRegistry.getInstrumentation().targetContext
        assertTrue(context.packageName.startsWith("com.luminet.android"))

        val gate = UnderlayLifecycleGate()
        val first = gate.start()
        assertTrue(gate.isCurrent(first))

        gate.stop()
        assertFalse(gate.isCurrent(first))

        val second = gate.start()
        assertTrue(second > first)
        assertFalse(gate.isCurrent(first))
        assertTrue(gate.isCurrent(second))
    }
}
