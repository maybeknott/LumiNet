package com.luminet.android.tunnel

/**
 * Tunnel health evaluation states representing connection lifecycle and quality.
 */
enum class TunnelHealthVerdict {
    DISCONNECTED,
    STARTING,
    WORKING,
    DEGRADED,
    RECONNECT_NEEDED,
    BROKEN,
    WAITING_FOR_TRAFFIC
}

/**
 * Encryption strength tiers for tunnel configuration.
 */
enum class EncryptionLevel {
    STANDARD,
    STRONG,
    MAXIMUM
}

/**
 * FEC (Forward Error Correction) profile parameters for loss compensation.
 */
data class FecProfile(
    val name: String,
    val lossTolerancePct: Int,
    val redundancyPct: Int,
    val flushTimeoutMs: Int
) {
    companion object {
        val NONE = FecProfile("None", 0, 0, 0)
        val CONSERVATIVE = FecProfile("Conservative", 8, 15, 25)
        val BALANCED = FecProfile("Balanced", 12, 25, 20)
        val AGGRESSIVE = FecProfile("Aggressive", 16, 40, 15)

        fun fromName(name: String): FecProfile = when (name.lowercase()) {
            "conservative" -> CONSERVATIVE
            "balanced" -> BALANCED
            "aggressive" -> AGGRESSIVE
            else -> NONE
        }
    }
}

/**
 * Telemetry observed from Android VpnService or packet tunnel session.
 */
data class TunnelMetrics(
    val packetsTx: Long = 0L,
    val packetsRx: Long = 0L,
    val bytesTx: Long = 0L,
    val bytesRx: Long = 0L,
    val latencyMs: Long = 0L,
    val lossRatio: Double = 0.0,
    val consecutiveFailures: Int = 0,
    val lastHandshakeAgeSec: Long = 0L
)

/**
 * Evaluates health and manages profile redaction for mobile tunnels.
 */
object TunnelHealthDiagnostics {

    private val SECRET_PATTERNS = listOf(
        Regex("(?i)(password\\s*[:=]\\s*)[^\\r\\n,;]+"),
        Regex("(?i)(private_key\\s*[:=]\\s*)[^\\r\\n,;]+"),
        Regex("(?i)(preshared_key\\s*[:=]\\s*)[^\\r\\n,;]+"),
        Regex("(?i)(token\\s*[:=]\\s*)[^\\r\\n,;]+"),
        Regex("(?i)(secret\\s*[:=]\\s*)[^\\r\\n,;]+")
    )

    fun evaluate(metrics: TunnelMetrics): TunnelHealthVerdict {
        if (metrics.packetsTx == 0L && metrics.packetsRx == 0L && metrics.lastHandshakeAgeSec == 0L) {
            return TunnelHealthVerdict.DISCONNECTED
        }
        if (metrics.packetsTx > 0L && metrics.packetsRx == 0L && metrics.lastHandshakeAgeSec < 10L && metrics.consecutiveFailures == 0) {
            return TunnelHealthVerdict.STARTING
        }
        if (metrics.consecutiveFailures >= 5 || metrics.lastHandshakeAgeSec > 180L) {
            return TunnelHealthVerdict.BROKEN
        }
        if (metrics.consecutiveFailures >= 3 || metrics.lastHandshakeAgeSec > 60L || metrics.lossRatio > 0.35) {
            return TunnelHealthVerdict.RECONNECT_NEEDED
        }
        if (metrics.lossRatio > 0.10 || metrics.latencyMs > 350L) {
            return TunnelHealthVerdict.DEGRADED
        }
        if (metrics.packetsTx > 0L && metrics.packetsRx == 0L && metrics.lastHandshakeAgeSec >= 10L) {
            return TunnelHealthVerdict.WAITING_FOR_TRAFFIC
        }
        return TunnelHealthVerdict.WORKING
    }

    fun recommendFec(lossRatio: Double, isCellular: Boolean): FecProfile {
        return when {
            lossRatio > 0.15 || (isCellular && lossRatio > 0.08) -> FecProfile.AGGRESSIVE
            lossRatio > 0.05 || isCellular -> FecProfile.BALANCED
            lossRatio > 0.01 -> FecProfile.CONSERVATIVE
            else -> FecProfile.NONE
        }
    }

    fun stripSecrets(config: String): String {
        var sanitized = config
        for (pattern in SECRET_PATTERNS) {
            sanitized = pattern.replace(sanitized, "$1[REDACTED]")
        }
        return sanitized
    }
}
