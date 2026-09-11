package com.luminet.android.tunnel

import java.net.URI
import java.util.concurrent.atomic.AtomicLong
import java.util.regex.Pattern

/**
 * Backend proxy node reachability prober and duplex session traffic meter.
 *
 */
data class BackendProbeConfig(
    val targetUrl: String,
    val path: String? = null,
    val timeoutMs: Long = 5000L
)

data class BackendProbeResult(
    val ok: Boolean,
    val backendMode: Boolean,
    val backendUrl: String,
    val targetTried: String,
    val upstreamStatus: Int?,
    val gotWebSocket: Boolean,
    val elapsedMs: Long,
    val serverHeader: String?,
    val steps: List<String>,
    val fixHint: String?
)

class BackendProbeDiagnostic {

    private val ipv4Pattern = Pattern.compile("^\\d{1,3}\\.\\d{1,3}\\.\\d{1,3}\\.\\d{1,3}$")

    fun formatWsHandshake(targetUrl: String, overridePath: String? = null): Triple<String, String, String> {
        val trimmed = targetUrl.trim()
        require(trimmed.startsWith("http://") || trimmed.startsWith("https://")) {
            "Backend URL must start with http:// or https://"
        }

        val uri = URI.create(trimmed)
        val host = uri.host ?: throw IllegalArgumentException("Malformed backend host")
        val port = uri.port

        val finalPath = if (!overridePath.isNullOrBlank()) {
            if (overridePath.startsWith("/")) overridePath else "/$overridePath"
        } else {
            val existing = uri.path
            if (existing.isNullOrBlank() || existing == "/") "/novavpn" else existing
        }

        val targetTried = "${uri.scheme}://${if (port != -1) "$host:$port" else host}$finalPath"
        val request = buildString {
            append("GET $finalPath HTTP/1.1\r\n")
            append("Host: $host\r\n")
            append("Upgrade: websocket\r\n")
            append("Connection: Upgrade\r\n")
            append("Sec-WebSocket-Key: dGhlIHNhbXBsZSBub25jZQ==\r\n")
            append("Sec-WebSocket-Version: 13\r\n\r\n")
        }

        return Triple(request, targetTried, host)
    }

    fun evaluateResponse(
        status: Int,
        serverHeader: String?,
        targetHost: String,
        elapsedMs: Long,
        isWebSocket: Boolean
    ): Pair<List<String>, String?> {
        val steps = mutableListOf<String>()
        var fixHint: String? = null

        if (status == 101 && isWebSocket) {
            steps.add("SUCCESS: Backend reached and upgraded to WebSocket (101). Relay path works.")
            return Pair(steps, null)
        }

        val isRawIp = ipv4Pattern.matcher(targetHost).matches()

        if (status == 403) {
            if (isRawIp && elapsedMs < 100L) {
                steps.add("403 in ${elapsedMs}ms to RAW IP — Edge SSRF sandbox blocks bare IP.")
                fixHint = "Use a gray-cloud (DNS-only) A record in Backend URL instead of raw IP."
            } else {
                steps.add("Backend returned 403. Check that path matches Xray wsSettings.path and Host header is accepted.")
                fixHint = "Verify wsSettings.path and inbound Host whitelist."
            }
        } else {
            steps.add("Backend did NOT upgrade. Status $status. Server header: '${serverHeader ?: ""}'. Check port and path.")
        }

        return Pair(steps, fixHint)
    }
}

class DuplexTrafficMeter(val userId: String) {
    private val upBytes = AtomicLong(0)
    private val downBytes = AtomicLong(0)

    fun recordUp(bytes: Long) {
        if (bytes > 0) upBytes.addAndGet(bytes)
    }

    fun recordDown(bytes: Long) {
        if (bytes > 0) downBytes.addAndGet(bytes)
    }

    fun getUpBytes(): Long = upBytes.get()
    fun getDownBytes(): Long = downBytes.get()
    fun totalBytes(): Long = upBytes.get() + downBytes.get()
}
