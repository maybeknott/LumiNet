package com.luminet.android.tunnel

import java.util.concurrent.ConcurrentHashMap

data class AndroidProbeResponse(
    val statusCode: Int,
    val headers: Map<String, String>,
    val body: ByteArray
)

class EmbeddedProbeServer(
    val host: String,
    val port: Int
) {
    private var authHeaderExpected: String? = null
    private val payloads = ConcurrentHashMap<String, ByteArray>()

    fun setAuth(user: String, pass: String) {
        authHeaderExpected = "Basic $user:$pass"
    }

    fun registerPayload(path: String, data: ByteArray) {
        payloads[path] = data
    }

    fun handleRequest(method: String, path: String, authHeader: String?, rangeHeader: String?): AndroidProbeResponse {
        val headers = mutableMapOf("Server" to "LumiProbe-Android/1.0")

        authHeaderExpected?.let { expected ->
            if (authHeader != expected) {
                headers["WWW-Authenticate"] = "Basic realm=\"LumiProbe\""
                return AndroidProbeResponse(401, headers, "Unauthorized".toByteArray())
            }
        }

        if (path == "/health" || path == "/ping") {
            headers["Content-Type"] = "text/plain"
            return AndroidProbeResponse(200, headers, "OK".toByteArray())
        }

        if (path.startsWith("/probe/bandwidth")) {
            val bytes = ByteArray(64 * 1024) { 0x55.toByte() }
            headers["Content-Type"] = "application/octet-stream"
            headers["Content-Length"] = bytes.size.toString()
            return AndroidProbeResponse(200, headers, bytes)
        }

        payloads[path]?.let { payload ->
            headers["Content-Type"] = "application/octet-stream"
            if (rangeHeader != null && rangeHeader.startsWith("bytes=")) {
                val spec = rangeHeader.removePrefix("bytes=").split("-")
                if (spec.size == 2) {
                    val start = spec[0].toIntOrNull() ?: 0
                    val end = spec[1].toIntOrNull()?.coerceAtMost(payload.size - 1) ?: (payload.size - 1)
                    if (start <= end && start < payload.size) {
                        val slice = payload.copyOfRange(start, end + 1)
                        headers["Content-Range"] = "bytes $start-$end/${payload.size}"
                        headers["Content-Length"] = slice.size.toString()
                        return AndroidProbeResponse(206, headers, slice)
                    }
                }
            }
            headers["Content-Length"] = payload.size.toString()
            return AndroidProbeResponse(200, headers, payload)
        }

        return AndroidProbeResponse(404, headers, "Not Found".toByteArray())
    }
}
