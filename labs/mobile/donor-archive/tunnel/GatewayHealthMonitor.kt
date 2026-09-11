// Copyright 2024-2026 LumiNet Authors. All Rights Reserved.
package com.luminet.android.tunnel

enum class GatewayStatus {
    ONLINE,
    DEGRADED,
    OFFLINE
}

data class GatewayMetric(
    val ip: String,
    var latencyMs: Double = 0.0,
    var packetLoss: Double = 0.0,
    var status: GatewayStatus = GatewayStatus.ONLINE
)

class GatewayHealthMonitor(
    private val lossDegraded: Double = 0.20,
    private val lossOffline: Double = 0.50
) {
    private val gateways = mutableMapOf<String, GatewayMetric>()
    private val lock = Any()

    fun registerGateway(ip: String) = synchronized(lock) {
        gateways[ip] = GatewayMetric(ip)
    }

    fun recordProbe(ip: String, latencyMs: Double, loss: Double) = synchronized(lock) {
        val gw = gateways[ip] ?: return
        gw.latencyMs = latencyMs
        gw.packetLoss = loss
        gw.status = when {
            loss >= lossOffline -> GatewayStatus.OFFLINE
            loss >= lossDegraded -> GatewayStatus.DEGRADED
            else -> GatewayStatus.ONLINE
        }
    }

    fun selectActiveGateway(primaryIp: String, backupIp: String): String = synchronized(lock) {
        val primary = gateways[primaryIp]
        if (primary != null && primary.status == GatewayStatus.ONLINE) {
            return primaryIp
        }
        val backup = gateways[backupIp]
        if (backup != null && backup.status != GatewayStatus.OFFLINE) {
            return backupIp
        }
        primaryIp
    }
}
