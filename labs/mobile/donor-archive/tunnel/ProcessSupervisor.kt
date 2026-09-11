package com.luminet.android.tunnel

enum class ProcessState {
    STOPPED,
    STARTING,
    RUNNING,
    CRASHED
}

class ProcessSupervisor(
    val maxRestarts: Int = 5,
    val baseBackoffMs: Long = 1000L,
    val maxBackoffMs: Long = 30000L
) {
    var state: ProcessState = ProcessState.STOPPED
        private set
    var restartCount: Int = 0
        private set
    private var currentBackoff: Long = baseBackoffMs

    fun recordCrash(): Long? {
        state = ProcessState.CRASHED
        restartCount++
        if (restartCount > maxRestarts) {
            return null // Do not restart
        }
        val backoff = currentBackoff
        currentBackoff = (currentBackoff * 2).coerceAtMost(maxBackoffMs)
        return backoff
    }

    fun markRunning() {
        state = ProcessState.RUNNING
        currentBackoff = baseBackoffMs
    }

    fun reset() {
        state = ProcessState.STOPPED
        restartCount = 0
        currentBackoff = baseBackoffMs
    }
}
