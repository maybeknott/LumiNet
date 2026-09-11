package com.luminet.android.tunnel

/**
 * RFC 8484 DoH Client & SNI Fragment Forwarder Engine for Android clients.
 */
object DohProxyEngine {

    const val DOH_CONTENT_TYPE = "application/dns-message"

    data class DohClientConfig(
        val endpointUrl: String = "https://cloudflare-dns.com/dns-query",
        val customSni: String? = "cloudflare-dns.com",
        val timeoutMs: Long = 5000L,
        val fragmentationStrategy: String = "sni_split"
    )

    /**
     * Validates that an incoming payload is a valid RFC 1035 DNS response.
     * Header must be >= 12 bytes and the QR bit (bit 15) must be 1.
     */
    fun validateDohResponse(body: ByteArray): Boolean {
        if (body.size < 12) return false
        val flags = ((body[2].toInt() and 0xFF) shl 8) or (body[3].toInt() and 0xFF)
        val isResponse = (flags and 0x8000) != 0
        return isResponse
    }

    /**
     * Scans a TLS ClientHello packet to locate the byte offset and length where the SNI hostname begins.
     */
    fun findSniHostnameOffset(data: ByteArray): Pair<Int, Int>? {
        if (data.size < 44 || data[0] != 0x16.toByte()) {
            return null
        }

        var pos = 5 + 4 // TLS record header (5) + handshake header (4)
        pos += 2 // version
        pos += 32 // random

        if (pos >= data.size) return null
        val sessionIdLen = data[pos].toInt() and 0xFF
        pos += 1 + sessionIdLen

        if (pos + 2 > data.size) return null
        val cipherSuitesLen = ((data[pos].toInt() and 0xFF) shl 8) or (data[pos + 1].toInt() and 0xFF)
        pos += 2 + cipherSuitesLen

        if (pos + 1 > data.size) return null
        val compMethodsLen = data[pos].toInt() and 0xFF
        pos += 1 + compMethodsLen

        if (pos + 2 > data.size) return null
        val extensionsLen = ((data[pos].toInt() and 0xFF) shl 8) or (data[pos + 1].toInt() and 0xFF)
        pos += 2
        val extensionsEnd = Math.min(pos + extensionsLen, data.size)

        while (pos + 4 <= extensionsEnd) {
            val extType = ((data[pos].toInt() and 0xFF) shl 8) or (data[pos + 1].toInt() and 0xFF)
            val extLen = ((data[pos + 2].toInt() and 0xFF) shl 8) or (data[pos + 3].toInt() and 0xFF)
            pos += 4

            if (extType == 0x0000 && extLen > 0) {
                // list_length(2) + name_type(1) + hostname_length(2) + hostname
                if (pos + 5 <= extensionsEnd) {
                    val hostLen = ((data[pos + 3].toInt() and 0xFF) shl 8) or (data[pos + 4].toInt() and 0xFF)
                    val hostStart = pos + 5
                    if (hostStart + hostLen <= data.size) {
                        return Pair(hostStart, hostLen)
                    }
                }
            }
            pos += extLen
        }

        return null
    }

    /**
     * Splits a TLS ClientHello packet across TCP segment boundaries.
     */
    fun splitClientHello(data: ByteArray, strategy: String = "sni_split"): List<ByteArray> {
        return when (strategy) {
            "sni_split" -> {
                val found = findSniHostnameOffset(data)
                if (found != null) {
                    val (offset, hostLen) = found
                    var mid = if (hostLen > 0) offset + hostLen / 2 else offset + (data.size - offset) / 2
                    if (mid <= 0) mid = 1
                    if (mid >= data.size) mid = data.size - 1
                    listOf(data.copyOfRange(0, mid), data.copyOfRange(mid, data.size))
                } else {
                    splitHalf(data)
                }
            }
            "half" -> splitHalf(data)
            "multi" -> splitMulti(data, 24)
            else -> splitHalf(data)
        }
    }

    fun splitHalf(data: ByteArray): List<ByteArray> {
        if (data.size <= 1) return listOf(data.clone())
        val mid = data.size / 2
        return listOf(data.copyOfRange(0, mid), data.copyOfRange(mid, data.size))
    }

    fun splitMulti(data: ByteArray, chunkSize: Int = 24): List<ByteArray> {
        val size = if (chunkSize <= 0) 24 else chunkSize
        val chunks = mutableListOf<ByteArray>()
        var offset = 0
        while (offset < data.size) {
            val end = Math.min(offset + size, data.size)
            chunks.add(data.copyOfRange(offset, end))
            offset = end
        }
        return chunks
    }

    fun reconstruct(chunks: List<ByteArray>): ByteArray {
        val total = chunks.sumOf { it.size }
        val out = ByteArray(total)
        var offset = 0
        for (c in chunks) {
            System.arraycopy(c, 0, out, offset, c.size)
            offset += c.size
        }
        return out
    }
}
