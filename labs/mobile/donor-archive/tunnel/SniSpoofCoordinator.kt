package com.luminet.android.tunnel

import java.nio.ByteBuffer
import java.nio.ByteOrder

/**
 * Android SNI Spoof and DPI Desync Coordinator.
 */
data class SniSpoofProfile(
    val connectIp: String = "127.0.0.1",
    val connectPort: Int = 443,
    val fakeSni: String = "speedtest.net",
    val fastMode: Boolean = true
)

object CloudflareCidrMatcher {
    val CIDRS = listOf(
        "173.245.48.0/20", "103.21.244.0/22", "103.22.200.0/22", "103.31.4.0/22",
        "141.101.64.0/18", "108.162.192.0/18", "190.93.240.0/20", "188.114.96.0/20",
        "197.234.240.0/22", "198.41.128.0/17", "162.158.0.0/15", "104.16.0.0/13",
        "104.24.0.0/14", "172.64.0.0/13", "131.0.72.0/22"
    )

    private val parsedRanges: List<Pair<Long, Long>> = CIDRS.mapNotNull { parseCidr(it) }

    fun isCloudflareIp(ipStr: String): Boolean {
        val ipVal = parseIpv4ToLong(ipStr) ?: return false
        for ((network, mask) in parsedRanges) {
            if ((ipVal and mask) == network) {
                return true
            }
        }
        return false
    }

    private fun parseIpv4ToLong(ipStr: String): Long? {
        val parts = ipStr.trim().split(".")
        if (parts.size != 4) return null
        var result = 0L
        for (p in parts) {
            val num = p.toLongOrNull() ?: return null
            if (num !in 0..255) return null
            result = (result shl 8) or num
        }
        return result
    }

    private fun parseCidr(cidr: String): Pair<Long, Long>? {
        val parts = cidr.split("/")
        if (parts.size != 2) return null
        val ipVal = parseIpv4ToLong(parts[0]) ?: return null
        val prefix = parts[1].toIntOrNull() ?: return null
        if (prefix !in 0..32) return null
        val mask = if (prefix == 0) 0L else (0xFFFFFFFFL shl (32 - prefix)) and 0xFFFFFFFFL
        return Pair(ipVal and mask, mask)
    }
}

object SniDomainCleaner {
    fun cleanDomain(raw: String): String? {
        var s = raw.trim()
        if (s.isEmpty() || s.startsWith("#")) return null
        val schemeIdx = s.indexOf("://")
        if (schemeIdx != -1) s = s.substring(schemeIdx + 3)
        val pathIdx = s.indexOf('/')
        if (pathIdx != -1) s = s.substring(0, pathIdx)
        val portIdx = s.indexOf(':')
        if (portIdx != -1) s = s.substring(0, portIdx)
        val cleaned = s.trim().lowercase()
        if (cleaned.isEmpty() || cleaned.contains(' ') || !cleaned.contains('.')) return null
        return cleaned
    }
}

object TlsClientHelloTemplate {
    fun build(fakeSni: String, random: ByteArray, sessionId: ByteArray, keyShare: ByteArray): ByteArray {
        val sniBytes = fakeSni.toByteArray(Charsets.US_ASCII)
        val sniExt = ByteBuffer.allocate(7 + sniBytes.size).order(ByteOrder.BIG_ENDIAN).apply {
            putShort((sniBytes.size + 5).toShort())
            putShort((sniBytes.size + 3).toShort())
            put(0.toByte()) // HostName type
            putShort(sniBytes.size.toShort())
            put(sniBytes)
        }.array()

        val padLen = if (sniBytes.size <= 219) 219 - sniBytes.size else 0
        val padExt = ByteBuffer.allocate(2 + padLen).order(ByteOrder.BIG_ENDIAN).apply {
            putShort(padLen.toShort())
            put(ByteArray(padLen))
        }.array()

        // 517-byte canonical buffer
        val out = ByteArray(517)
        var cursor = 0

        // TLS Record Header (5 bytes: 0x16, 0x03, 0x01, 0x02, 0x00) + Handshake Header (6 bytes: 0x01, 0x00, 0x01, 0xfc, 0x03, 0x03)
        val static1 = byteArrayOf(0x16, 0x03, 0x01, 0x02, 0x00, 0x01, 0x00, 0x01.toByte(), 0xfc.toByte(), 0x03, 0x03)
        System.arraycopy(static1, 0, out, cursor, static1.size)
        cursor += static1.size

        System.arraycopy(random, 0, out, cursor, 32)
        cursor += 32

        out[cursor++] = 0x20.toByte() // Session ID length

        System.arraycopy(sessionId, 0, out, cursor, 32)
        cursor += 32

        // Cipher suites + compression (44 bytes)
        val static3 = byteArrayOf(
            0x00, 0x24, 0x13, 0x02, 0x13, 0x03, 0x13, 0x01, 0xc0.toByte(), 0x2c.toByte(),
            0xc0.toByte(), 0x30.toByte(), 0xc0.toByte(), 0x2b.toByte(), 0xc0.toByte(), 0x2f.toByte(),
            0xcc.toByte(), 0xa9.toByte(), 0xcc.toByte(), 0xa8.toByte(), 0xc0.toByte(), 0x24.toByte(),
            0xc0.toByte(), 0x28.toByte(), 0xc0.toByte(), 0x23.toByte(), 0xc0.toByte(), 0x27.toByte(),
            0x00, 0x9f.toByte(), 0x00, 0x9e.toByte(), 0x00, 0x6b, 0x00, 0x67,
            0x00, 0xff.toByte(), 0x01, 0x00, 0x01.toByte(), 0x8f.toByte(), 0x00, 0x00
        )
        System.arraycopy(static3, 0, out, cursor, static3.size)
        cursor += static3.size

        System.arraycopy(sniExt, 0, out, cursor, sniExt.size)
        cursor += sniExt.size

        // Extensions between SNI and KeyShare (129 bytes)
        val static4 = byteArrayOf(
            0x00, 0x0b, 0x00, 0x04, 0x03, 0x00, 0x01, 0x02, 0x00, 0x0a, 0x00, 0x16, 0x00, 0x14, 0x00, 0x1d,
            0x00, 0x17, 0x00, 0x1e, 0x00, 0x19, 0x00, 0x18, 0x01, 0x00, 0x01, 0x01, 0x01, 0x02, 0x01, 0x03,
            0x01, 0x04, 0x00, 0x23, 0x00, 0x00, 0x00, 0x10, 0x00, 0x0e, 0x00, 0x0c, 0x02, 0x68, 0x32, 0x08,
            0x68, 0x74, 0x74, 0x70, 0x2f, 0x31, 0x2e, 0x31, 0x00, 0x16, 0x00, 0x00, 0x00, 0x17, 0x00, 0x00,
            0x00, 0x0d, 0x00, 0x2a, 0x00, 0x28, 0x04, 0x03, 0x05, 0x03, 0x06, 0x03, 0x08, 0x07, 0x08, 0x08,
            0x08, 0x09, 0x08, 0x0a, 0x08, 0x0b, 0x08, 0x04, 0x08, 0x05, 0x08, 0x06, 0x04, 0x01, 0x05, 0x01,
            0x06, 0x01, 0x03, 0x03, 0x03, 0x01, 0x03, 0x02, 0x04, 0x02, 0x05, 0x02, 0x06, 0x02, 0x00, 0x2b,
            0x00, 0x05, 0x04, 0x03, 0x04, 0x03, 0x03, 0x00, 0x2d, 0x00, 0x02, 0x01, 0x01, 0x00, 0x33, 0x00,
            0x26, 0x00, 0x24, 0x00, 0x1d, 0x00, 0x20
        )
        System.arraycopy(static4, 0, out, cursor, static4.size)
        cursor += static4.size

        System.arraycopy(keyShare, 0, out, cursor, 32)
        cursor += 32

        out[cursor++] = 0x00 // Padding Extension Type 0x0015
        out[cursor++] = 0x15

        System.arraycopy(padExt, 0, out, cursor, padExt.size)
        return out
    }
}

class OutboundKillSwitchGuard(var enabled: Boolean = true) {
    var armedSni: Boolean = false
    var armedCore: Boolean = false
    var isBlocked: Boolean = false

    fun onHeartbeat(sniRunning: Boolean, coreRunning: Boolean): Boolean {
        if (!enabled) {
            isBlocked = false
            return false
        }
        if (!armedSni && !armedCore) return false
        val dropped = (armedSni && !sniRunning) || (armedCore && !coreRunning)
        if (dropped && !isBlocked) {
            isBlocked = true
            return true // Trigger block
        }
        return false
    }

    fun disarm(sni: Boolean, core: Boolean): Boolean {
        if (sni) armedSni = false
        if (core) armedCore = false
        if (!armedSni && !armedCore && isBlocked) {
            isBlocked = false
            return true // Restore unblock
        }
        return false
    }
}
