package com.luminet.android.scanner

import kotlinx.coroutines.runBlocking
import org.junit.Assert.*
import org.junit.Test

class NodeSpeedtestManagerTest {

    @Test
    fun testDefaultConfig() {
        val config = SpeedtestConfig()
        assertEquals(4, config.concurrency)
        assertEquals(3000, config.probeTimeoutMs)
        assertTrue(config.realPingUrl.contains("generate_204"))
    }

    @Test
    fun testCandidateSpeedResultFormatting() {
        val res = CandidateSpeedResult(
            target = "127.0.0.1:8080",
            action = SpeedActionType.TCP_PING,
            success = true,
            latencyMs = 45L
        )
        assertTrue(res.success)
        assertEquals(45L, res.latencyMs)
        assertEquals(SpeedActionType.TCP_PING, res.action)
    }

    @Test
    fun testCancellationLifecycle() = runBlocking {
        val manager = NodeSpeedtestManager()
        manager.cancel()
        val results = manager.evaluateBatch(
            SpeedActionType.TCP_PING,
            listOf("127.0.0.1:80", "1.1.1.1:53")
        )
        assertEquals(2, results.size)
        assertTrue(results.all { !it.success && it.error == "Cancelled" })

        manager.reset()
    }
}
