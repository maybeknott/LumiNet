package com.luminet.android.tunnel

data class ProbeResult(
    val timestamp: Long,
    val success: Boolean,
    val latencyMs: Long
)

class UptimeTracker(val maxHistory: Int = 50) {
    private val history = mutableListOf<ProbeResult>()
    private var totalChecks = 0
    private var failedChecks = 0

    fun record(success: Boolean, latencyMs: Long) {
        totalChecks++
        if (!success) failedChecks++

        history.add(ProbeResult(System.currentTimeMillis(), success, latencyMs))
        if (history.size > maxHistory) {
            history.removeAt(0)
        }
    }

    fun availability(): Double {
        if (totalChecks == 0) return 100.0
        val passed = totalChecks - failedChecks
        return (passed.toDouble() / totalChecks.toDouble()) * 100.0
    }

    fun historyCount(): Int = history.size
}
