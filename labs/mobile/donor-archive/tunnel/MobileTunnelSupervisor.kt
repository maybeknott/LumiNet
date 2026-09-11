package com.luminet.android.tunnel

enum class AndroidTunnelState {
    DISCONNECTED, CONNECTING, CONNECTED, RECONNECTING, STOPPED
}

enum class SplitTunnelMode {
    ALLOW_ALL, EXCLUDE_PACKAGES, INCLUDE_PACKAGES
}

data class MobileSupervisorConfig(
    val splitMode: SplitTunnelMode = SplitTunnelMode.ALLOW_ALL,
    val packages: Set<String> = emptySet(),
    val primaryDns: String = "1.1.1.1",
    val fallbackDns: String = "8.8.8.8",
    val autoReconnect: Boolean = true
)

class MobileTunnelSupervisor(var config: MobileSupervisorConfig = MobileSupervisorConfig()) {
    var state: AndroidTunnelState = AndroidTunnelState.DISCONNECTED
        private set

    private var reconnectCount = 0

    fun startTunnel() {
        state = AndroidTunnelState.CONNECTING
        // Establish connection
        state = AndroidTunnelState.CONNECTED
        reconnectCount = 0
    }

    fun stopTunnel() {
        state = AndroidTunnelState.STOPPED
    }

    fun handleNetworkDrop() {
        if (config.autoReconnect && state == AndroidTunnelState.CONNECTED) {
            state = AndroidTunnelState.RECONNECTING
            reconnectCount++
        } else {
            state = AndroidTunnelState.DISCONNECTED
        }
    }

    fun isAppRouted(packageName: String): Boolean {
        return when (config.splitMode) {
            SplitTunnelMode.ALLOW_ALL -> true
            SplitTunnelMode.EXCLUDE_PACKAGES -> !config.packages.contains(packageName)
            SplitTunnelMode.INCLUDE_PACKAGES -> config.packages.contains(packageName)
        }
    }

    fun getEffectiveDns(useFallback: Boolean): String {
        return if (useFallback) config.fallbackDns else config.primaryDns
    }

    fun getReconnectAttempts(): Int = reconnectCount
}
