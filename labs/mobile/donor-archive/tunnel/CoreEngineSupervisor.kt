package com.luminet.android.tunnel

enum class AndroidCoreEngineState {
    STOPPED,
    STARTING,
    RUNNING,
    DEGRADED,
    CRASHED
}

data class AndroidEngineMetrics(
    var pid: Int = 0,
    var uptimeSeconds: Long = 0,
    var memoryRssBytes: Long = 0,
    var restartCount: Int = 0
)

data class AndroidSupervisorConfig(
    val maxRestarts: Int = 5,
    val memoryLimitBytes: Long = 256 * 1024 * 1024L
)

class CoreEngineSupervisor(val config: AndroidSupervisorConfig = AndroidSupervisorConfig()) {
    var state: AndroidCoreEngineState = AndroidCoreEngineState.STOPPED
        private set
    val metrics = AndroidEngineMetrics()

    fun start(pid: Int): Boolean {
        if (state == AndroidCoreEngineState.RUNNING) return false
        state = AndroidCoreEngineState.RUNNING
        metrics.pid = pid
        metrics.uptimeSeconds = 0
        return true
    }

    fun stop(): Boolean {
        state = AndroidCoreEngineState.STOPPED
        metrics.pid = 0
        return true
    }

    fun handleProcessExit(exitCode: Int): AndroidCoreEngineState {
        if (exitCode == 0) {
            state = AndroidCoreEngineState.STOPPED
            metrics.pid = 0
        } else {
            metrics.restartCount++
            state = if (metrics.restartCount > config.maxRestarts) {
                AndroidCoreEngineState.CRASHED
            } else {
                AndroidCoreEngineState.DEGRADED
            }
        }
        return state
    }

    fun recordHeartbeat(elapsedSeconds: Long, currentRssBytes: Long): Boolean {
        if (state != AndroidCoreEngineState.RUNNING && state != AndroidCoreEngineState.DEGRADED) {
            return false
        }
        metrics.uptimeSeconds += elapsedSeconds
        metrics.memoryRssBytes = currentRssBytes

        if (currentRssBytes > config.memoryLimitBytes) {
            state = AndroidCoreEngineState.DEGRADED
            return false
        }
        return true
    }
}
