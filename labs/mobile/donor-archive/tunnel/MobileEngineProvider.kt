package com.luminet.android.tunnel

enum class MobileEngineState {
    STOPPED,
    STARTING,
    RUNNING,
    DEGRADED,
    STOPPING,
    ERROR
}

data class MobileEngineMetrics(
    var uptimeSecs: Long = 0,
    var rxBytes: Long = 0,
    var txBytes: Long = 0,
    var activeTunnels: Int = 0,
    var lastHeartbeat: Long = 0
)

data class MobileEngineConfig(
    val bindAddress: String = "127.0.0.1",
    val socks5Port: Int = 10808,
    val httpPort: Int = 10809,
    val dnsPort: Int = 5353,
    val mtu: Int = 1500,
    val enableIPv6: Boolean = false
)

class MobileEngineProvider(val config: MobileEngineConfig) {
    var state: MobileEngineState = MobileEngineState.STOPPED
        private set
    val metrics = MobileEngineMetrics()
    private var startTime: Long = 0

    fun startEngine(timestamp: Long) {
        if (state == MobileEngineState.RUNNING) {
            throw IllegalStateException("Engine already running")
        }
        if (config.socks5Port <= 0 || config.httpPort <= 0) {
            state = MobileEngineState.ERROR
            throw IllegalArgumentException("Invalid port configuration")
        }

        state = MobileEngineState.STARTING
        startTime = timestamp
        metrics.lastHeartbeat = timestamp
        metrics.activeTunnels = 1
        state = MobileEngineState.RUNNING
    }

    fun stopEngine() {
        if (state == MobileEngineState.STOPPED) return
        state = MobileEngineState.STOPPING
        metrics.activeTunnels = 0
        state = MobileEngineState.STOPPED
    }

    fun recordTraffic(rx: Long, tx: Long, timestamp: Long) {
        metrics.rxBytes += rx
        metrics.txBytes += tx
        metrics.lastHeartbeat = timestamp
        if (startTime > 0 && timestamp >= startTime) {
            metrics.uptimeSecs = timestamp - startTime
        }
    }

    fun markDegraded(degraded: Boolean) {
        if (state == MobileEngineState.RUNNING && degraded) {
            state = MobileEngineState.DEGRADED
        } else if (state == MobileEngineState.DEGRADED && !degraded) {
            state = MobileEngineState.RUNNING
        }
    }
}
