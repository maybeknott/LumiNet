package com.luminet.android.tunnel

class HttpChunkCarrier(
    val host: String,
    val path: String,
    val sessionId: String
) {
    fun createUplinkHeader(): ByteArray {
        val hdr = "POST $path HTTP/1.1\r\nHost: $host\r\nTransfer-Encoding: chunked\r\nContent-Type: application/octet-stream\r\nX-Session-ID: $sessionId\r\nConnection: keep-alive\r\n\r\n"
        return hdr.toByteArray(Charsets.US_ASCII)
    }

    companion object {
        fun encodeChunk(payload: ByteArray): ByteArray {
            val hex = Integer.toHexString(payload.size)
            val prefix = "$hex\r\n".toByteArray(Charsets.US_ASCII)
            val suffix = "\r\n".toByteArray(Charsets.US_ASCII)
            return prefix + payload + suffix
        }

        fun decodeChunk(data: ByteArray): Pair<ByteArray, Int>? {
            val str = String(data, Charsets.US_ASCII)
            val idx = str.indexOf("\r\n")
            if (idx < 0) return null
            val hex = str.substring(0, idx).trim()
            val size = hex.toIntOrNull(16) ?: return null
            val dataStart = idx + 2
            val dataEnd = dataStart + size
            if (data.size < dataEnd + 2) return null
            val payload = data.copyOfRange(dataStart, dataEnd)
            return Pair(payload, dataEnd + 2)
        }
    }
}
