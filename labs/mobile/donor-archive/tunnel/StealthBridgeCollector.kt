package com.luminet.android.tunnel

import java.util.concurrent.ConcurrentHashMap

enum class AndroidPluggableTransport {
    OBFS4,
    SNOWFLAKE,
    WEBTUNNEL,
    MEEK,
    CUSTOM
}

data class AndroidStealthBridge(
    val transport: AndroidPluggableTransport,
    val endpoint: String,
    val fingerprint: String,
    val params: Map<String, String>,
    var score: Double = 1.0,
    var latencyMs: Int = 0,
    var verified: Boolean = false
)

class StealthBridgeCollector(val minScoreThreshold: Double = 0.5) {
    private val bridges = ConcurrentHashMap<String, AndroidStealthBridge>()

    fun parseBridgeLine(line: String): AndroidStealthBridge {
        val trimmed = line.trim()
        if (trimmed.isEmpty() || trimmed.startsWith("#")) {
            throw IllegalArgumentException("Empty or comment line")
        }

        val parts = trimmed.split(Regex("\\s+"))
        if (parts.size < 3) throw IllegalArgumentException("Insufficient tokens")

        val transport = when (parts[0].lowercase()) {
            "obfs4" -> AndroidPluggableTransport.OBFS4
            "snowflake" -> AndroidPluggableTransport.SNOWFLAKE
            "webtunnel" -> AndroidPluggableTransport.WEBTUNNEL
            "meek" -> AndroidPluggableTransport.MEEK
            else -> AndroidPluggableTransport.CUSTOM
        }

        val endpoint = parts[1]
        val fingerprint = parts[2].uppercase()

        val params = mutableMapOf<String, String>()
        for (token in parts.drop(3)) {
            val kv = token.split("=", limit = 2)
            if (kv.size == 2) {
                params[kv[0]] = kv[1]
            }
        }

        val bridge = AndroidStealthBridge(
            transport = transport,
            endpoint = endpoint,
            fingerprint = fingerprint,
            params = params
        )
        bridges[fingerprint] = bridge
        return bridge
    }

    fun recordHealth(fingerprint: String, latencyMs: Int, success: Boolean): Boolean {
        val bridge = bridges[fingerprint.uppercase()] ?: return false
        if (success) {
            bridge.verified = true
            bridge.latencyMs = latencyMs
            val factor = minOf(2.0, 1000.0 / maxOf(50, latencyMs))
            bridge.score = (bridge.score * 0.8) + (1.2 * factor)
        } else {
            bridge.score *= 0.5
            if (bridge.score < 0.1) bridge.verified = false
        }
        return true
    }

    fun getBestBridges(transport: AndroidPluggableTransport?, limit: Int): List<AndroidStealthBridge> {
        return bridges.values
            .filter { (transport == null || it.transport == transport) && it.score >= minScoreThreshold }
            .sortedByDescending { it.score }
            .take(limit)
    }
}
