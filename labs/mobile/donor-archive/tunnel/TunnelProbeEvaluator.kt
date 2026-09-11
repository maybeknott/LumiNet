package com.luminet.android.tunnel

import kotlin.math.round
import kotlin.math.sqrt

data class AttemptMetric(
    val success: Boolean,
    val durationMs: Long,
    val errorCategory: String? = null
)

data class TcpProbeResult(
    val success: Boolean,
    val attempts: List<AttemptMetric> = emptyList(),
    val medianRttMs: Long = 0L,
    val consistency: Double = 0.0,
    val errorCategory: String? = null
)

data class TlsProbeResult(
    val success: Boolean,
    val handshakeMs: Long = 0L,
    val version: String? = null,
    val cipherSuite: String? = null,
    val alpn: String? = null,
    val verified: Boolean = false,
    val errorCategory: String? = null
)

data class HttpProbeItem(
    val method: String,
    val url: String,
    val statusCode: Int,
    val durationMs: Long,
    val redirected: Boolean = false,
    val errorCategory: String? = null
)

data class HttpProbeResult(
    val success: Boolean,
    val probes: List<HttpProbeItem> = emptyList()
)

data class WsProbeResult(
    val success: Boolean,
    val statusCode: Int = 0,
    val durationMs: Long = 0L,
    val errorCategory: String? = null
)

data class UdpProbeResult(
    val reachable: Boolean,
    val attempts: List<AttemptMetric> = emptyList(),
    val errorCategory: String? = null
)

data class QuicProbeResult(
    val success: Boolean,
    val handshakeMs: Long = 0L,
    val alpn: String? = null,
    val errorCategory: String? = null
)

data class DnsProbeResult(
    val udpResponsive: Boolean,
    val tcpResponsive: Boolean,
    val answers: List<String> = emptyList(),
    val attempts: List<AttemptMetric> = emptyList(),
    val errorCategory: String? = null
)

data class ProbeMetrics(
    val rttMs: Long,
    val jitterMs: Long,
    val packetLossEstimate: Double,
    val stabilityPercent: Double,
    val timeoutFrequency: Double
)

data class ScoreResult(
    val numeric: Int,
    val grade: String,
    val classification: String,
    val confidence: Double,
    val falsePositive: Boolean,
    val reasons: List<String>
)

object TunnelProbeEvaluator {

    fun computeMetrics(
        tcp: TcpProbeResult,
        udp: UdpProbeResult,
        dns: DnsProbeResult
    ): ProbeMetrics {
        val attempts = mutableListOf<AttemptMetric>()
        attempts.addAll(tcp.attempts)
        attempts.addAll(udp.attempts)
        attempts.addAll(dns.attempts)

        val successfulDurations = mutableListOf<Long>()
        var timeouts = 0

        for (a in attempts) {
            if (a.success) {
                successfulDurations.add(a.durationMs)
            }
            if (a.errorCategory != null && a.errorCategory.equals("timeout", ignoreCase = true)) {
                timeouts++
            }
        }

        val jitter = if (successfulDurations.size > 1) {
            val sum = successfulDurations.sumOf { it.toDouble() }
            val mean = sum / successfulDurations.size
            val variance = successfulDurations.sumOf {
                val d = it.toDouble() - mean
                d * d
            } / successfulDurations.size
            round(sqrt(variance)).toLong()
        } else {
            0L
        }

        val rtt = if (tcp.medianRttMs > 0) {
            tcp.medianRttMs
        } else {
            medianLatency(successfulDurations)
        }

        val totalAttempts = attempts.size
        val successRatio = if (totalAttempts > 0) {
            attempts.count { it.success }.toDouble() / totalAttempts.toDouble()
        } else {
            0.0
        }

        val loss = 1.0 - successRatio
        val timeoutFreq = if (totalAttempts > 0) {
            timeouts.toDouble() / totalAttempts.toDouble()
        } else {
            0.0
        }

        var stability = 100.0 * (1.0 - loss)
        if (jitter > 250) {
            stability -= 15.0
        }
        if (timeoutFreq > 0.25) {
            stability -= 20.0
        }
        if (stability < 0.0) {
            stability = 0.0
        }

        return ProbeMetrics(
            rttMs = rtt,
            jitterMs = jitter,
            packetLossEstimate = roundTwoDec(loss * 100.0),
            stabilityPercent = roundTwoDec(stability),
            timeoutFrequency = roundTwoDec(timeoutFreq * 100.0)
        )
    }

    fun scoreProbe(
        tcp: TcpProbeResult,
        tls: TlsProbeResult,
        http: HttpProbeResult,
        ws: WsProbeResult,
        quic: QuicProbeResult,
        dns: DnsProbeResult,
        metrics: ProbeMetrics
    ): ScoreResult {
        var points = 0
        val reasons = mutableListOf<String>()

        if (tcp.success) {
            points += 25
            reasons.add("tcp_connectivity")
        }
        if (tcp.consistency >= 0.67) {
            points += 15
            reasons.add("retry_consistency")
        }
        if (tls.success) {
            points += 20
            reasons.add("tls_handshake")
        }
        if (http.success) {
            points += 8
            reasons.add("http_behavior")
        }
        if (ws.success) {
            points += 10
            reasons.add("websocket_upgrade")
        }
        if (quic.success) {
            points += 8
            reasons.add("quic_handshake")
        }
        if (dns.udpResponsive || dns.tcpResponsive) {
            points += 6
            reasons.add("dns_responsive")
        }

        if (metrics.rttMs in 1..149) {
            points += 5
        }
        if (metrics.jitterMs < 80) {
            points += 5
        }
        if (metrics.stabilityPercent >= 90.0) {
            points += 8
        }
        if (points > 100) {
            points = 100
        }

        var falsePositive = tcp.success && tcp.consistency < 0.67
        if (tcp.success && !tls.success && !http.success && !ws.success && !quic.success && !dns.udpResponsive && !dns.tcpResponsive) {
            falsePositive = true
        }

        val classification = when {
            falsePositive -> "False Positive"
            points >= 82 && tcp.consistency >= 0.67 && (tls.success || ws.success || quic.success) -> "Tunnel Ready"
            points >= 58 -> "Partially Usable"
            points >= 38 -> "Unstable"
            else -> "Blocked"
        }

        val grade = calculateGrade(points)
        val conf = calculateConfidence(tcp, tls, http, ws, quic, metrics, falsePositive)

        return ScoreResult(
            numeric = points,
            grade = grade,
            classification = classification,
            confidence = roundTwoDec(conf),
            falsePositive = falsePositive,
            reasons = reasons
        )
    }

    fun parseCloudflareTrace(raw: String): Pair<String?, String?> {
        var ip: String? = null
        var countryCode: String? = null
        for (line in raw.lines()) {
            val parts = line.trim().split("=", limit = 2)
            if (parts.size == 2) {
                val key = parts[0].trim()
                val value = parts[1].trim()
                when (key) {
                    "ip" -> if (value.isNotEmpty()) ip = value
                    "loc" -> if (value.isNotEmpty()) countryCode = value.uppercase()
                }
            }
        }
        return Pair(ip, countryCode)
    }

    private fun calculateGrade(points: Int): String {
        return when {
            points >= 94 -> "A+"
            points >= 85 -> "A"
            points >= 72 -> "B"
            points >= 58 -> "C"
            points >= 38 -> "D"
            else -> "F"
        }
    }

    private fun calculateConfidence(
        tcp: TcpProbeResult,
        tls: TlsProbeResult,
        http: HttpProbeResult,
        ws: WsProbeResult,
        quic: QuicProbeResult,
        metrics: ProbeMetrics,
        falsePositive: Boolean
    ): Double {
        var c = tcp.consistency * 45.0
        if (tls.success) c += 20.0
        if (http.success || ws.success || quic.success) c += 20.0
        if (metrics.stabilityPercent >= 85.0) c += 15.0
        if (falsePositive) c -= 25.0
        if (c < 0.0) c = 0.0
        if (c > 100.0) c = 100.0
        return c
    }

    private fun medianLatency(values: List<Long>): Long {
        if (values.isEmpty()) return 0L
        val sorted = values.sorted()
        return sorted[sorted.size / 2]
    }

    private fun roundTwoDec(v: Double): Double {
        return round(v * 100.0) / 100.0
    }
}
