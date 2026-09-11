package com.luminet.android.tunnel

enum class SystemProxyMode {
    DIRECT,
    PAC,
    GLOBAL,
    MANUAL
}

data class DesktopStatus(
    val mode: SystemProxyMode,
    val activeProfile: String,
    val httpPort: Int,
    val socks5Port: Int,
    val isConnected: Boolean,
    val pacUrl: String?
)

class DesktopClientManager(val httpPort: Int, val socks5Port: Int) {
    var mode: SystemProxyMode = SystemProxyMode.DIRECT
        private set
    var activeProfile: String = "default"
        private set
    var isConnected: Boolean = false
        private set
    var pacUrl: String? = null
        private set

    fun setProxyMode(newMode: SystemProxyMode, url: String? = null) {
        if (newMode == SystemProxyMode.PAC && url == null && pacUrl == null) {
            throw IllegalArgumentException("PAC mode requires PAC URL")
        }
        mode = newMode
        if (url != null) pacUrl = url
    }

    fun switchProfile(profile: String) {
        activeProfile = profile
    }

    fun setConnected(connected: Boolean) {
        isConnected = connected
    }

    fun getStatus(): DesktopStatus {
        return DesktopStatus(
            mode = mode,
            activeProfile = activeProfile,
            httpPort = httpPort,
            socks5Port = socks5Port,
            isConnected = isConnected,
            pacUrl = pacUrl
        )
    }

    fun handleIpcCommand(command: String, payload: Map<String, Any>): Map<String, Any> {
        return when (command) {
            "get_status" -> mapOf(
                "mode" to mode.name,
                "active_profile" to activeProfile,
                "is_connected" to isConnected
            )
            "set_mode" -> {
                val mStr = payload["mode"] as? String ?: throw IllegalArgumentException("Missing mode")
                val url = payload["pac_url"] as? String
                setProxyMode(SystemProxyMode.valueOf(mStr.uppercase()), url)
                mapOf("success" to true)
            }
            "switch_profile" -> {
                val prof = payload["profile"] as? String ?: throw IllegalArgumentException("Missing profile")
                switchProfile(prof)
                mapOf("success" to true, "profile" to prof)
            }
            else -> throw IllegalArgumentException("Unknown IPC command: $command")
        }
    }
}
