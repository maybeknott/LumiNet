package com.luminet.android.tunnel

data class AndroidEdgeIpRecord(
    val ipAddress: String,
    var latencyMs: Long = Long.MAX_VALUE,
    var packetLossRatio: Float = 1.0f,
    var isAvailable: Boolean = false
)

class EdgeCdnPoolSorter(private val maxLatencyThresholdMs: Long = 300) {
    private val ipPool = mutableMapOf<String, AndroidEdgeIpRecord>()

    fun addIp(ip: String) {
        ipPool[ip] = AndroidEdgeIpRecord(ipAddress = ip)
    }

    fun updateProbeResult(ip: String, latencyMs: Long, success: Boolean) {
        val entry = ipPool[ip] ?: return
        if (success) {
            entry.latencyMs = latencyMs
            entry.packetLossRatio = 0.0f
            entry.isAvailable = latencyMs <= maxLatencyThresholdMs
        } else {
            entry.packetLossRatio = 1.0f
            entry.isAvailable = false
        }
    }

    fun getSortedFastest(): List<AndroidEdgeIpRecord> {
        return ipPool.values
            .filter { it.isAvailable }
            .sortedBy { it.latencyMs }
    }

    fun bestIp(): String? {
        return getSortedFastest().firstOrNull()?.ipAddress
    }
}
