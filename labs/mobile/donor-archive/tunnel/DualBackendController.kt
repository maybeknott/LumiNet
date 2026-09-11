package com.luminet.android.tunnel

enum class AndroidBackendEngine {
    KCP_RAW_SOCKET,
    VIOLATED_TCP_QUIC,
    FALLBACK_STANDARD
}

data class AndroidEngineHealth(
    var rttMs: Long = 100L,
    var packetLoss: Float = 0f,
    var consecutiveFails: Int = 0,
    var isAlive: Boolean = true
)

class DualBackendController {
    val engines = mutableMapOf<AndroidBackendEngine, AndroidEngineHealth>()
    var activeEngine: AndroidBackendEngine = AndroidBackendEngine.KCP_RAW_SOCKET

    init {
        engines[AndroidBackendEngine.KCP_RAW_SOCKET] = AndroidEngineHealth()
        engines[AndroidBackendEngine.VIOLATED_TCP_QUIC] = AndroidEngineHealth()
        engines[AndroidBackendEngine.FALLBACK_STANDARD] = AndroidEngineHealth()
    }

    fun recordMetrics(engine: AndroidBackendEngine, rtt: Long, loss: Float, success: Boolean) {
        val h = engines[engine] ?: return
        h.rttMs = rtt
        h.packetLoss = loss
        if (success) {
            h.consecutiveFails = 0
            h.isAlive = true
        } else {
            h.consecutiveFails++
            if (h.consecutiveFails >= 3) {
                h.isAlive = false
            }
        }
    }

    fun selectEngine(): AndroidBackendEngine {
        if (engines[activeEngine]?.isAlive == true) {
            return activeEngine
        }
        for (eng in listOf(AndroidBackendEngine.KCP_RAW_SOCKET, AndroidBackendEngine.VIOLATED_TCP_QUIC, AndroidBackendEngine.FALLBACK_STANDARD)) {
            if (engines[eng]?.isAlive == true) {
                activeEngine = eng
                return eng
            }
        }
        return AndroidBackendEngine.FALLBACK_STANDARD
    }
}
