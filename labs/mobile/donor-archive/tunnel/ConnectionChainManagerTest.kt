package com.luminet.android.tunnel

import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertTrue
import org.junit.Assert.fail
import org.junit.Test

class ConnectionChainManagerTest {

    @Test
    fun testDisabledChainReturnsBaseOnly() {
        val base = ChainProfileRef("sub1", "fp_base", "Primary Relay")
        val settings = ChainSettings(enabled = false)

        val resolved = ConnectionChainManager.resolveChain(base, settings)
        assertEquals(1, resolved.hops.size)
        assertEquals("fp_base", resolved.hops[0].fingerprint)
        assertFalse(resolved.isChained)
    }

    @Test
    fun test3HopChain() {
        val before = ChainProfileRef("sub1", "fp_before", "Bridge Pre-Hop")
        val base = ChainProfileRef("sub1", "fp_base", "Primary Relay")
        val after = ChainProfileRef("sub2", "fp_after", "Egress Exit")

        val settings = ChainSettings(
            enabled = true,
            before = ChainHop(ChainSlot.Before, HopMode.Fixed, before),
            after = ChainHop(ChainSlot.After, HopMode.Fixed, after)
        )

        val resolved = ConnectionChainManager.resolveChain(base, settings)
        assertEquals(3, resolved.hops.size)
        assertEquals("fp_before", resolved.hops[0].fingerprint)
        assertEquals("fp_base", resolved.hops[1].fingerprint)
        assertEquals("fp_after", resolved.hops[2].fingerprint)
        assertTrue(resolved.isChained)
    }

    @Test
    fun testLoopDetectionThrows() {
        val base = ChainProfileRef("sub1", "fp_dup", "Duplicate Node")
        val settings = ChainSettings(
            enabled = true,
            before = ChainHop(ChainSlot.Before, HopMode.Fixed, base)
        )

        try {
            ConnectionChainManager.resolveChain(base, settings)
            fail("Expected IllegalStateException for loop")
        } catch (_: IllegalStateException) {
            // expected
        }
    }
}
