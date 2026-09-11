package com.luminet.android.tunnel

import org.junit.Assert.*
import org.junit.Test

class TunnelHealthDiagnosticsTest {

    @Test
    fun testEvaluationVerdicts() {
        // Disconnected
        assertEquals(
            TunnelHealthVerdict.DISCONNECTED,
            TunnelHealthDiagnostics.evaluate(TunnelMetrics())
        )

        // Starting
        assertEquals(
            TunnelHealthVerdict.STARTING,
            TunnelHealthDiagnostics.evaluate(TunnelMetrics(packetsTx = 10, packetsRx = 0, lastHandshakeAgeSec = 2))
        )

        // Waiting for traffic
        assertEquals(
            TunnelHealthVerdict.WAITING_FOR_TRAFFIC,
            TunnelHealthDiagnostics.evaluate(TunnelMetrics(packetsTx = 10, packetsRx = 0, lastHandshakeAgeSec = 12))
        )

        // Degraded latency
        assertEquals(
            TunnelHealthVerdict.DEGRADED,
            TunnelHealthDiagnostics.evaluate(TunnelMetrics(packetsTx = 50, packetsRx = 50, latencyMs = 400, lastHandshakeAgeSec = 2))
        )

        // Degraded loss
        assertEquals(
            TunnelHealthVerdict.DEGRADED,
            TunnelHealthDiagnostics.evaluate(TunnelMetrics(packetsTx = 50, packetsRx = 40, lossRatio = 0.15, lastHandshakeAgeSec = 2))
        )

        // Reconnect needed
        assertEquals(
            TunnelHealthVerdict.RECONNECT_NEEDED,
            TunnelHealthDiagnostics.evaluate(TunnelMetrics(packetsTx = 50, packetsRx = 30, lossRatio = 0.40, lastHandshakeAgeSec = 2))
        )

        // Broken
        assertEquals(
            TunnelHealthVerdict.BROKEN,
            TunnelHealthDiagnostics.evaluate(TunnelMetrics(packetsTx = 50, packetsRx = 0, consecutiveFailures = 5, lastHandshakeAgeSec = 2))
        )

        // Broken due to handshake age
        assertEquals(
            TunnelHealthVerdict.BROKEN,
            TunnelHealthDiagnostics.evaluate(TunnelMetrics(packetsTx = 50, packetsRx = 50, consecutiveFailures = 0, lastHandshakeAgeSec = 200))
        )

        // Working
        assertEquals(
            TunnelHealthVerdict.WORKING,
            TunnelHealthDiagnostics.evaluate(TunnelMetrics(packetsTx = 100, packetsRx = 99, latencyMs = 30, lossRatio = 0.01, lastHandshakeAgeSec = 2))
        )
    }

    @Test
    fun testFecRecommendations() {
        assertEquals(FecProfile.AGGRESSIVE, TunnelHealthDiagnostics.recommendFec(0.20, false))
        assertEquals(FecProfile.AGGRESSIVE, TunnelHealthDiagnostics.recommendFec(0.10, true))
        assertEquals(FecProfile.BALANCED, TunnelHealthDiagnostics.recommendFec(0.02, true))
        assertEquals(FecProfile.CONSERVATIVE, TunnelHealthDiagnostics.recommendFec(0.02, false))
        assertEquals(FecProfile.NONE, TunnelHealthDiagnostics.recommendFec(0.005, false))
    }

    @Test
    fun testStripSecrets() {
        val conf = "host=vpn.example.com\npassword=supersecret\nprivate_key=privkey123"
        val sanitized = TunnelHealthDiagnostics.stripSecrets(conf)
        assertFalse(sanitized.contains("supersecret"))
        assertFalse(sanitized.contains("privkey123"))
        assertTrue(sanitized.contains("[REDACTED]"))
        assertTrue(sanitized.contains("host=vpn.example.com"))
    }
}
