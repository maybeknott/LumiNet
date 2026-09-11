package com.luminet.android.tunnel

import org.junit.Assert.*
import org.junit.Test

class CombinedBypassEngineTest {

    @Test
    fun testPlanWithTtlDecoy() {
        val realHello = "123456789012345678901234567890123456789012345678901234567890".toByteArray()
        val fakeHello = "FAKE_CLIENT_HELLO_SNI".toByteArray()

        val config = CombinedBypassEngine.CombinedBypassConfig(
            mode = CombinedBypassEngine.BypassMode.COMBINED_TTL_DECOY,
            fakeSni = "decoy.example.com",
            useTtlTrick = true,
            ttlHops = 3,
            fragmentStrategy = "sni_split",
            fragmentDelayMs = 15L
        )

        val plan = CombinedBypassEngine.plan(realHello, fakeHello, config)

        assertNotNull(plan.decoyProbe)
        assertEquals(3, plan.decoyProbe?.ttl)
        assertArrayEquals(fakeHello, plan.decoyProbe?.payload)

        assertTrue(plan.fragments.size >= 2)
        assertEquals(0L, plan.fragments[0].delayMs)
        assertEquals(15L, plan.fragments[1].delayMs)

        val reconstructed = CombinedBypassEngine.reconstructPayload(plan)
        assertArrayEquals(realHello, reconstructed)
    }

    @Test
    fun testPlanWithoutDecoy() {
        val realHello = "test_tls_payload".toByteArray()
        val config = CombinedBypassEngine.CombinedBypassConfig(
            mode = CombinedBypassEngine.BypassMode.SNI_FRAGMENT,
            useTtlTrick = false,
            fragmentStrategy = "half",
            fragmentDelayMs = 5L
        )

        val plan = CombinedBypassEngine.plan(realHello, ByteArray(0), config)
        assertNull(plan.decoyProbe)
        assertEquals(2, plan.fragments.size)
    }

    @Test
    fun testSelectOptimalMode() {
        val results = listOf(
            CombinedBypassEngine.DomainEvaluationResult(
                domain = "youtube.com",
                mode = CombinedBypassEngine.BypassMode.DIRECT,
                success = false,
                latencyMs = 5000L
            ),
            CombinedBypassEngine.DomainEvaluationResult(
                domain = "youtube.com",
                mode = CombinedBypassEngine.BypassMode.SNI_FRAGMENT,
                success = false,
                latencyMs = 4000L
            ),
            CombinedBypassEngine.DomainEvaluationResult(
                domain = "youtube.com",
                mode = CombinedBypassEngine.BypassMode.COMBINED_TTL_DECOY,
                success = true,
                latencyMs = 120L
            )
        )

        val mode = CombinedBypassEngine.selectOptimalMode(results)
        assertEquals(CombinedBypassEngine.BypassMode.COMBINED_TTL_DECOY, mode)

        // Add a successful direct mode which should be preferred
        val resultsWithDirect = results + CombinedBypassEngine.DomainEvaluationResult(
            domain = "youtube.com",
            mode = CombinedBypassEngine.BypassMode.DIRECT,
            success = true,
            latencyMs = 40L
        )
        val optimal = CombinedBypassEngine.selectOptimalMode(resultsWithDirect)
        assertEquals(CombinedBypassEngine.BypassMode.DIRECT, optimal)
    }
}
