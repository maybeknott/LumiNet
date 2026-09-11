package com.luminet.android.tunnel

data class RelayClientConfig(
    val relayHost: String,
    val relayPort: Int,
    val authToken: String,
    val targetHost: String,
    val targetPort: Int
)

class HttpRelayTunnelClient(val config: RelayClientConfig) {
    fun buildConnectPayload(): String {
        val authHeader = if (config.authToken.isNotBlank()) {
            "Proxy-Authorization: Bearer ${config.authToken}\r\n"
        } else {
            ""
        }
        return "CONNECT ${config.targetHost}:${config.targetPort} HTTP/1.1\r\n" +
               "Host: ${config.targetHost}:${config.targetPort}\r\n" +
               "Proxy-Connection: Keep-Alive\r\n" +
               authHeader +
               "\r\n"
    }
}
