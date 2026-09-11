package com.luminet.android.tunnel

import java.util.concurrent.ConcurrentHashMap

data class AndroidSubsystemHealth(
    val name: String,
    val plane: String,
    var isHealthy: Boolean = true,
    var activeConnections: Int = 0,
    var lastHeartbeatMs: Long = 0,
    var lastError: String? = null
)

data class AndroidGlobalReport(
    val totalSubsystems: Int,
    val healthySubsystems: Int,
    val healthPercentage: Float,
    val totalActiveConnections: Int,
    val killswitchEngaged: Boolean
)

class AutonomousGlobalProxySupervisor(val autoRemediationEnabled: Boolean = true) {
    val subsystems = ConcurrentHashMap<String, AndroidSubsystemHealth>()
    var killswitchEngaged: Boolean = false
        private set

    fun registerSubsystem(name: String, plane: String) {
        subsystems[name] = AndroidSubsystemHealth(name, plane)
    }

    fun updateHealth(name: String, healthy: Boolean, conns: Int, nowMs: Long, error: String? = null): Boolean {
        val sub = subsystems[name] ?: return false
        sub.isHealthy = healthy
        sub.activeConnections = conns
        sub.lastHeartbeatMs = nowMs
        sub.lastError = error
        return true
    }

    fun setKillswitch(engaged: Boolean) {
        killswitchEngaged = engaged
        if (engaged) {
            for (sub in subsystems.values) {
                sub.activeConnections = 0
            }
        }
    }

    fun generateReport(): AndroidGlobalReport {
        val total = subsystems.size
        val healthy = subsystems.values.count { it.isHealthy }
        val conns = subsystems.values.sumOf { it.activeConnections }
        val pct = if (total == 0) 100f else (healthy.toFloat() / total.toFloat()) * 100f

        return AndroidGlobalReport(
            totalSubsystems = total,
            healthySubsystems = healthy,
            healthPercentage = pct,
            totalActiveConnections = conns,
            killswitchEngaged = killswitchEngaged
        )
    }

    fun identifyRemediationTargets(nowMs: Long, staleTimeoutMs: Long): List<String> {
        if (!autoRemediationEnabled) return emptyList()

        return subsystems.values
            .filter { !it.isHealthy || (nowMs - it.lastHeartbeatMs > staleTimeoutMs && it.lastHeartbeatMs > 0) }
            .map { it.name }
    }
}
