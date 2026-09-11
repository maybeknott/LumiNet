package com.luminet.android.tunnel

import java.io.ByteArrayInputStream
import java.io.ByteArrayOutputStream
import java.io.DataInputStream
import java.io.DataOutputStream
import java.net.Inet4Address
import java.net.InetAddress
import java.nio.ByteBuffer
import java.nio.ByteOrder
import java.nio.charset.StandardCharsets

/**
 * Multi-Protocol Inbound Proxy Demultiplexer & Wire Framer.
 *
 * Ported and unified from `proxy-main`.
 * Provides single-port multiplexing for HTTP, HTTPS CONNECT, SOCKS4, SOCKS4a, SOCKS5, and SOCKS5h
 * by inspecting the opening byte of incoming connections and parsing command frames.
 */
enum class ProxyProtocolKind {
    HTTP,
    SOCKS4,
    SOCKS5
}

object MixedProtocolConstants {
    const val SOCKS4_VERSION: Byte = 0x04
    const val SOCKS4_CMD_CONNECT: Byte = 0x01
    const val SOCKS4_CMD_BIND: Byte = 0x02

    const val SOCKS4_STATUS_GRANTED: Byte = 0x5a
    const val SOCKS4_STATUS_REJECTED: Byte = 0x5b
    const val SOCKS4_STATUS_NO_IDENTD: Byte = 0x5c
    const val SOCKS4_STATUS_INVALID_USER: Byte = 0x5d

    const val SOCKS5_VERSION: Byte = 0x05
    const val SOCKS5_AUTH_NONE: Byte = 0x00
    const val SOCKS5_AUTH_NO_ACCEPTABLE: Byte = 0xff.toByte()

    const val SOCKS5_CMD_CONNECT: Byte = 0x01
    const val SOCKS5_CMD_BIND: Byte = 0x02
    const val SOCKS5_CMD_UDP_ASSOCIATE: Byte = 0x03

    const val SOCKS5_ATYP_IPV4: Byte = 0x01
    const val SOCKS5_ATYP_DOMAIN: Byte = 0x03
    const val SOCKS5_ATYP_IPV6: Byte = 0x04

    const val SOCKS5_REP_SUCCESS: Byte = 0x00
    const val SOCKS5_REP_GENERAL_FAILURE: Byte = 0x01
    const val SOCKS5_REP_CONNECTION_NOT_ALLOWED: Byte = 0x02
    const val SOCKS5_REP_NETWORK_UNREACHABLE: Byte = 0x03
    const val SOCKS5_REP_HOST_UNREACHABLE: Byte = 0x04
    const val SOCKS5_REP_CONNECTION_REFUSED: Byte = 0x05
    const val SOCKS5_REP_TTL_EXPIRED: Byte = 0x06
    const val SOCKS5_REP_CMD_NOT_SUPPORTED: Byte = 0x07
    const val SOCKS5_REP_ADDR_NOT_SUPPORTED: Byte = 0x08
}

data class Socks4Request(
    val command: Byte,
    val port: Int,
    val ip: Inet4Address,
    val userId: String,
    val domain: String? = null
) {
    fun targetHost(): String = domain ?: ip.hostAddress ?: "0.0.0.0"

    fun isSocks4a(): Boolean {
        val octets = ip.address
        return octets[0] == 0.toByte() && octets[1] == 0.toByte() && octets[2] == 0.toByte() && octets[3] != 0.toByte()
    }
}

data class Socks5Greeting(
    val methods: ByteArray
) {
    override fun equals(other: Any?): Boolean {
        if (this === other) return true
        if (other !is Socks5Greeting) return false
        return methods.contentEquals(other.methods)
    }

    override fun hashCode(): Int {
        return methods.contentHashCode()
    }
}

data class Socks5Request(
    val command: Byte,
    val targetHost: String,
    val targetPort: Int,
    val addressType: Byte
)

data class HttpProxyRequest(
    val method: String,
    val host: String,
    val port: Int,
    val path: String,
    val isConnect: Boolean
)

object MixedProtocolProxy {
    fun detectProtocol(firstByte: Byte): ProxyProtocolKind {
        return when (firstByte) {
            MixedProtocolConstants.SOCKS5_VERSION -> ProxyProtocolKind.SOCKS5
            MixedProtocolConstants.SOCKS4_VERSION -> ProxyProtocolKind.SOCKS4
            else -> ProxyProtocolKind.HTTP
        }
    }

    fun parseSocks4Request(bytes: ByteArray): Pair<Socks4Request, Int> {
        if (bytes.size < 8) {
            throw IllegalArgumentException("Buffer too short for SOCKS4 header")
        }
        if (bytes[0] != MixedProtocolConstants.SOCKS4_VERSION) {
            throw IllegalArgumentException("Invalid SOCKS4 version: ${bytes[0]}")
        }

        val cmd = bytes[1]
        val port = ((bytes[2].toInt() and 0xFF) shl 8) or (bytes[3].toInt() and 0xFF)
        val ipBytes = byteArrayOf(bytes[4], bytes[5], bytes[6], bytes[7])
        val ip = InetAddress.getByAddress(ipBytes) as Inet4Address

        val is4a = (ipBytes[0] == 0.toByte() && ipBytes[1] == 0.toByte() && ipBytes[2] == 0.toByte() && ipBytes[3] != 0.toByte())

        var idx = 8
        while (idx < bytes.size && bytes[idx] != 0.toByte()) {
            idx++
        }
        if (idx >= bytes.size) {
            throw IllegalArgumentException("Unterminated user-id string in SOCKS4")
        }
        val userId = String(bytes, 8, idx - 8, StandardCharsets.UTF_8)
        idx++ // Skip null byte

        var domain: String? = null
        if (is4a) {
            val domainStart = idx
            while (idx < bytes.size && bytes[idx] != 0.toByte()) {
                idx++
            }
            if (idx >= bytes.size) {
                throw IllegalArgumentException("Unterminated domain string in SOCKS4a")
            }
            domain = String(bytes, domainStart, idx - domainStart, StandardCharsets.UTF_8)
            idx++ // Skip null byte
        }

        return Pair(Socks4Request(cmd, port, ip, userId, domain), idx)
    }

    fun buildSocks4Reply(status: Byte, bndPort: Int, bndIp: ByteArray = byteArrayOf(0, 0, 0, 0)): ByteArray {
        val out = ByteArrayOutputStream(8)
        out.write(0x00)
        out.write(status.toInt())
        out.write((bndPort shr 8) and 0xFF)
        out.write(bndPort and 0xFF)
        out.write(bndIp, 0, 4)
        return out.toByteArray()
    }

    fun parseSocks5Greeting(bytes: ByteArray): Pair<Socks5Greeting, Int> {
        if (bytes.size < 2) {
            throw IllegalArgumentException("Buffer too short for SOCKS5 greeting")
        }
        if (bytes[0] != MixedProtocolConstants.SOCKS5_VERSION) {
            throw IllegalArgumentException("Invalid SOCKS5 version: ${bytes[0]}")
        }
        val nmethods = bytes[1].toInt() and 0xFF
        val totalLen = 2 + nmethods
        if (bytes.size < totalLen) {
            throw IllegalArgumentException("Buffer too short for SOCKS5 greeting methods")
        }
        val methods = bytes.copyOfRange(2, totalLen)
        return Pair(Socks5Greeting(methods), totalLen)
    }

    fun buildSocks5GreetingReply(method: Byte): ByteArray {
        return byteArrayOf(MixedProtocolConstants.SOCKS5_VERSION, method)
    }

    fun parseSocks5Request(bytes: ByteArray): Pair<Socks5Request, Int> {
        if (bytes.size < 4) {
            throw IllegalArgumentException("Buffer too short for SOCKS5 command")
        }
        if (bytes[0] != MixedProtocolConstants.SOCKS5_VERSION) {
            throw IllegalArgumentException("Invalid SOCKS5 version: ${bytes[0]}")
        }

        val cmd = bytes[1]
        val atyp = bytes[3]
        var idx = 4

        val targetHost = when (atyp) {
            MixedProtocolConstants.SOCKS5_ATYP_IPV4 -> {
                if (bytes.size < idx + 4 + 2) throw IllegalArgumentException("Buffer too short for IPv4")
                val ip = InetAddress.getByAddress(bytes.copyOfRange(idx, idx + 4)).hostAddress ?: ""
                idx += 4
                ip
            }
            MixedProtocolConstants.SOCKS5_ATYP_DOMAIN -> {
                if (bytes.size < idx + 1) throw IllegalArgumentException("Buffer too short for domain len")
                val dlen = bytes[idx].toInt() and 0xFF
                idx += 1
                if (bytes.size < idx + dlen + 2) throw IllegalArgumentException("Buffer too short for domain")
                val dstr = String(bytes, idx, dlen, StandardCharsets.UTF_8)
                idx += dlen
                dstr
            }
            MixedProtocolConstants.SOCKS5_ATYP_IPV6 -> {
                if (bytes.size < idx + 16 + 2) throw IllegalArgumentException("Buffer too short for IPv6")
                val ip = InetAddress.getByAddress(bytes.copyOfRange(idx, idx + 16)).hostAddress ?: ""
                idx += 16
                ip
            }
            else -> throw IllegalArgumentException("Unsupported address type: $atyp")
        }

        if (bytes.size < idx + 2) {
            throw IllegalArgumentException("Buffer too short for port")
        }
        val targetPort = ((bytes[idx].toInt() and 0xFF) shl 8) or (bytes[idx + 1].toInt() and 0xFF)
        idx += 2

        return Pair(Socks5Request(cmd, targetHost, targetPort, atyp), idx)
    }

    fun buildSocks5Reply(rep: Byte, bndPort: Int, bndIp: ByteArray = byteArrayOf(127, 0, 0, 1)): ByteArray {
        val out = ByteArrayOutputStream(10)
        out.write(MixedProtocolConstants.SOCKS5_VERSION.toInt())
        out.write(rep.toInt())
        out.write(0x00) // RSV
        out.write(MixedProtocolConstants.SOCKS5_ATYP_IPV4.toInt())
        out.write(bndIp, 0, 4)
        out.write((bndPort shr 8) and 0xFF)
        out.write(bndPort and 0xFF)
        return out.toByteArray()
    }

    fun parseHttpProxyRequest(header: String): HttpProxyRequest {
        val line = header.lineSequence().firstOrNull()?.trim()
            ?: throw IllegalArgumentException("Malformed HTTP request line")
        val parts = line.split("\\s+".toRegex())
        if (parts.size < 2) {
            throw IllegalArgumentException("Malformed HTTP request: $line")
        }

        val method = parts[0].uppercase()
        val rawUri = parts[1]

        if (method == "CONNECT") {
            val (host, port) = parseHostPort(rawUri, 443)
            return HttpProxyRequest(
                method = method,
                host = host,
                port = port,
                path = "",
                isConnect = true
            )
        }

        val clean = rawUri.removePrefix("http://").removePrefix("https://")
        val slashIdx = clean.indexOf('/')
        val (hostPart, pathPart) = if (slashIdx >= 0) {
            Pair(clean.substring(0, slashIdx), clean.substring(slashIdx))
        } else {
            Pair(clean, "/")
        }

        val (host, port) = parseHostPort(hostPart, 80)
        return HttpProxyRequest(
            method = method,
            host = host,
            port = port,
            path = pathPart,
            isConnect = false
        )
    }

    fun buildHttpConnectOkResponse(): ByteArray {
        return "HTTP/1.1 200 Connection Established\r\nProxy-Agent: LumiNet-Mixed-Proxy/1.0\r\n\r\n".toByteArray(StandardCharsets.US_ASCII)
    }

    private fun parseHostPort(s: String, defaultPort: Int): Pair<String, Int> {
        val colonIdx = s.lastIndexOf(':')
        if (colonIdx >= 0) {
            val host = s.substring(0, colonIdx).trim('[', ']')
            val port = s.substring(colonIdx + 1).toIntOrNull() ?: defaultPort
            return Pair(host, port)
        }
        return Pair(s, defaultPort)
    }
}
