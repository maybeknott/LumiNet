package com.luminet.android.tunnel

import java.util.concurrent.ConcurrentHashMap

data class AndroidTlsBinding(
    val certPath: String,
    val keyPath: String,
    val sniDomain: String,
    val alpn: List<String> = listOf("h2", "http/1.1")
)

data class AndroidServerConfig(
    val localAddr: String = "0.0.0.0",
    val localPort: Int = 443,
    val remoteFallbackAddr: String = "127.0.0.1",
    val remoteFallbackPort: Int = 80,
    val passwords: List<String>,
    val tls: AndroidTlsBinding,
    val enableFastOpen: Boolean = true
)

class AutomatedTlsServerConfigurator {
    private val configs = ConcurrentHashMap<String, AndroidServerConfig>()

    fun registerServer(serverId: String, config: AndroidServerConfig) {
        configs[serverId] = config
    }

    fun generateJsonConfig(serverId: String): String? {
        val cfg = configs[serverId] ?: return null
        val passJson = cfg.passwords.joinToString(", ") { "\"$it\"" }
        val alpnJson = cfg.tls.alpn.joinToString(", ") { "\"$it\"" }

        return """
        {
          "run_type": "server",
          "local_addr": "${cfg.localAddr}",
          "local_port": ${cfg.localPort},
          "remote_addr": "${cfg.remoteFallbackAddr}",
          "remote_port": ${cfg.remoteFallbackPort},
          "password": [$passJson],
          "ssl": {
            "cert": "${cfg.tls.certPath}",
            "key": "${cfg.tls.keyPath}",
            "sni": "${cfg.tls.sniDomain}",
            "alpn": [$alpnJson]
          },
          "tcp": {
            "fast_open": ${cfg.enableFastOpen}
          }
        }
        """.trimIndent()
    }
}
