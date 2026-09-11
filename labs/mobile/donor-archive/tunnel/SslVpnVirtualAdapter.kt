package com.luminet.android.tunnel

data class SslVpnConfig(
    val gatewayIp: String,
    val virtualIp: String,
    val heartbeatPeriodMs: Long = 30000L
)

class SslVpnVirtualAdapter(val config: SslVpnConfig) {
    var isActive: Boolean = false
        private set
    var lastHeartbeatMs: Long = 0L
        private set
    var rxBytes: Long = 0L
        private set
    var txBytes: Long = 0L
        private set

    fun activate(): Boolean {
        if (isActive) return false
        isActive = true
        lastHeartbeatMs = System.currentTimeMillis()
        return true
    }

    fun heartbeat(): Boolean {
        if (!isActive) return false
        lastHeartbeatMs = System.currentTimeMillis()
        return true
    }

    fun recordTraffic(rx: Long, tx: Long) {
        rxBytes += rx
        txBytes += tx
    }
}
