package com.luminet.android.tunnel

import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertTrue
import org.junit.Test

class TunnelProbeEvaluatorTest {

    @Test
    fun testComputeMetrics() {
        val tcp = TcpProbeResult(
            success = true,
            attempts = listOf(
                AttemptMetric(true, 50),
                AttemptMetric(true, 70),
                AttemptMetric(true, 90)
            ),
            medianRttMs = 70,
            consistency = 1.0
        )
        val udp = UdpProbeResult(
            reachable = true,
            attempts = listOf(AttemptMetric(true, 60))
        )
        val dns = DnsProbeResult(
            udpResponsive = true,
            tcpResponsive = true,
            answers = listOf("1.1.1.1"),
            attempts = listOf(AttemptMetric(true, 80))
        )

        val metrics = TunnelProbeEvaluator.computeMetrics(tcp, udp, dns)
        assertEquals(70L, metrics.rttMs)
        assertEquals(14L, metrics.jitterMs)
        assertEquals(0.0, metrics.packetLossEstimate, 0.001)
        assertEquals(100.0, metrics.stabilityPercent, 0.001)
    }

    @Test
    fun testScoreProbeTunnelReady() {
        val tcp = TcpProbeResult(
            success = true,
            attempts = listOf(AttemptMetric(true, 40)),
            medianRttMs = 42,
            consistency = 1.0
        )
        val tls = TlsProbeResult(
            success = true,
            handshakeMs = 80,
            version = "TLS 1.3",
            verified = true
        )
        val http = HttpProbeResult(
            success = true,
            probes = listOf(HttpProbeItem("GET", "https://example.com/", 200, 60))
        )
        val ws = WsProbeResult(success = true, statusCode = 101, durationMs = 70)
        val quic = QuicProbeResult(success = true, handshakeMs = 65, alpn = "h3")
        val dns = DnsProbeResult(udpResponsive = true, tcpResponsive = true, answers = listOf("1.1.1.1"))
        val metrics = ProbeMetrics(42, 10, 0.0, 98.0, 0.0)

        val score = TunnelProbeEvaluator.scoreProbe(tcp, tls, http, ws, quic, dns, metrics)
        assertEquals("Tunnel Ready", score.classification)
        assertEquals("A+", score.grade)
        assertFalse(score.falsePositive)
        assertTrue(score.numeric >= 94)
    }

    @Test
    fun testScoreProbeFalsePositiveSpoofing() {
        val tcp = TcpProbeResult(success = true, medianRttMs = 20, consistency = 1.0)
        val tls = TlsProbeResult(success = false)
        val http = HttpProbeResult(success = false)
        val ws = WsProbeResult(success = false)
        val quic = QuicProbeResult(success = false)
        val dns = DnsProbeResult(udpResponsive = false, tcpResponsive = false)
        val metrics = ProbeMetrics(20, 2, 0.0, 100.0, 0.0)

        val score = TunnelProbeEvaluator.scoreProbe(tcp, tls, http, ws, quic, dns, metrics)
        assertTrue(score.falsePositive)
        assertEquals("False Positive", score.classification)
    }

    @Test
    fun testParseCloudflareTrace() {
        val trace = "fl=123f45\nip=198.51.100.42\nloc=ir\nts=1690000000\n"
        val (ip, loc) = TunnelProbeEvaluator.parseCloudflareTrace(trace)
        assertEquals("198.51.100.42", ip)
        assertEquals("IR", loc)
    }
}
