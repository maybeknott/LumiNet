package com.luminet.android.tunnel

data class DomainFrontingConfig(
    val frontDomain: String,
    val originHost: String,
    val requestPath: String = "/"
)

data class PreparedFrontedRequest(
    val sniDomain: String,
    val hostHeader: String,
    val path: String,
    val rawHeaderString: String
)

class DomainFrontingTransport {
    fun prepare(config: DomainFrontingConfig): PreparedFrontedRequest {
        require(config.frontDomain.isNotBlank()) { "frontDomain cannot be blank" }
        require(config.originHost.isNotBlank()) { "originHost cannot be blank" }

        val headers = "GET ${config.requestPath} HTTP/1.1\r\nHost: ${config.originHost}\r\nUser-Agent: Mozilla/5.0 (Android; Mobile)\r\n\r\n"
        return PreparedFrontedRequest(
            sniDomain = config.frontDomain,
            hostHeader = config.originHost,
            path = config.requestPath,
            rawHeaderString = headers
        )
    }
}
