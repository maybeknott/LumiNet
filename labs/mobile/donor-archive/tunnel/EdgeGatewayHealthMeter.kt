package com.luminet.android.tunnel

data class GatewayHealthMetric(
    val endpoint: String,
    val successRate: Float,
    val rttMs: Long,
    val activeConnections: Int,
    val isHealthy: Boolean
)

class EdgeGatewayHealthMeter(private val maxRttThresholdMs: Long = 500) {
    private val metrics = mutableMapOf<String, GatewayHealthMetric>()

    fun recordProbe(endpoint: String, rttMs: Long, success: Boolean, activeConns: Int) {
        val successRate = if (success) 1.0f else 0.0f
        val isHealthy = success && rttMs <= maxRttThresholdMs
        metrics[endpoint] = GatewayHealthMetric(
            endpoint = endpoint,
            successRate = successRate,
            rttMs = rttMs,
            activeConnections = activeConns,
            isHealthy = isHealthy
        )
    }

    fun getMetric(endpoint: String): GatewayHealthMetric? = metrics[endpoint]

    fun healthyGateways(): List<String> = metrics.filter { it.value.isHealthy }.map { it.key }

    fun selectBestGateway(): String? = metrics.values
        .filter { it.isHealthy }
        .minByOrNull { it.rttMs + (it.activeConnections * 5) }
        ?.endpoint
}
