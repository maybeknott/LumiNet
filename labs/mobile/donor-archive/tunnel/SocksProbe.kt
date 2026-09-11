package com.luminet.android.tunnel

import java.io.IOException
import java.io.InputStream
import java.io.OutputStream
import java.net.InetSocketAddress
import java.net.Socket

/**
 * Android local SOCKS5 tunnel reachability prober and stage tracker.
 *
 * Ported and unified from `oblivion-main` (`SocksProbe.kt` and `TunnelStage.kt`).
 * Validates that an active SOCKS5 proxy is capable of end-to-end egress by
 * connecting through SOCKS5, dispatching an HTTP GET to Cloudflare's trace edge,
 * and confirming an HTTP 200 status code before flipping the VPN UI state to CONNECTED.
 */
object SocksProbe {
    const val DEFAULT_CONNECT_TIMEOUT_MS = 4000
    const val DEFAULT_READ_TIMEOUT_MS = 4000

    const val DEFAULT_PROBE_HOST = "connectivity.cloudflareclient.com"
    const val DEFAULT_PROBE_PORT = 80
    const val DEFAULT_PROBE_PATH = "/cdn-cgi/trace"

    /**
     * Checks if a local SOCKS5 proxy on [socksPort] has functional upstream egress.
     */
    fun reachable(
        socksPort: Int,
        probeHost: String = DEFAULT_PROBE_HOST,
        probePort: Int = DEFAULT_PROBE_PORT,
        timeoutMs: Int = DEFAULT_CONNECT_TIMEOUT_MS,
    ): Boolean {
        return runCatching {
            performProbe(socksPort, probeHost, probePort, timeoutMs)
        }.getOrDefault(false)
    }

    private fun performProbe(
        socksPort: Int,
        host: String,
        port: Int,
        timeoutMs: Int,
    ): Boolean {
        Socket().use { socket ->
            socket.tcpNoDelay = true
            socket.soTimeout = timeoutMs
            socket.connect(InetSocketAddress("127.0.0.1", socksPort), timeoutMs)

            val output = socket.getOutputStream()
            val input = socket.getInputStream()

            if (!handshake(output, input)) return false
            if (!connectThrough(output, input, host, port)) return false

            val request = "GET $DEFAULT_PROBE_PATH HTTP/1.1\r\n" +
                    "Host: $host\r\n" +
                    "User-Agent: LumiNet/1.0\r\n" +
                    "Connection: close\r\n\r\n"
            output.write(request.toByteArray(Charsets.UTF_8))
            output.flush()

            val head = ByteArray(64)
            val read = input.read(head)
            if (read <= 0) return false

            val statusLine = String(head, 0, read, Charsets.UTF_8)
            return statusLine.contains(" 200")
        }
    }

    private fun handshake(output: OutputStream, input: InputStream): Boolean {
        // SOCKS5 version 5, 1 auth method, method 0 (no authentication)
        output.write(byteArrayOf(0x05, 0x01, 0x00))
        output.flush()

        val reply = ByteArray(2)
        if (!input.readFully(reply)) return false
        return reply[0] == 0x05.toByte() && reply[1] == 0x00.toByte()
    }

    private fun connectThrough(
        output: OutputStream,
        input: InputStream,
        host: String,
        port: Int,
    ): Boolean {
        val hostBytes = host.toByteArray(Charsets.UTF_8)
        if (hostBytes.size > 255) return false

        // CMD 0x01 (CONNECT), RSV 0x00, ATYP 0x03 (Domain name)
        val request = ByteArray(7 + hostBytes.size)
        request[0] = 0x05
        request[1] = 0x01
        request[2] = 0x00
        request[3] = 0x03
        request[4] = hostBytes.size.toByte()
        hostBytes.copyInto(request, 5)
        request[5 + hostBytes.size] = ((port shr 8) and 0xFF).toByte()
        request[6 + hostBytes.size] = (port and 0xFF).toByte()

        output.write(request)
        output.flush()

        val head = ByteArray(4)
        if (!input.readFully(head)) return false
        if (head[1] != 0x00.toByte()) return false // REP must be 0x00 (success)

        val trailing = when (head[3]) {
            0x01.toByte() -> 4 + 2 // IPv4 (4 bytes) + port (2 bytes)
            0x04.toByte() -> 16 + 2 // IPv6 (16 bytes) + port (2 bytes)
            0x03.toByte() -> {
                val lengthByte = ByteArray(1)
                if (!input.readFully(lengthByte)) return false
                (lengthByte[0].toInt() and 0xFF) + 2
            }
            else -> return false
        }

        return input.readFully(ByteArray(trailing))
    }

    private fun InputStream.readFully(buffer: ByteArray): Boolean {
        var offset = 0
        while (offset < buffer.size) {
            val read = try {
                read(buffer, offset, buffer.size - offset)
            } catch (_: IOException) {
                return false
            }
            if (read < 0) return false
            offset += read
        }
        return true
    }
}

/**
 * Tunnel lifecycle stages.
 */
enum class TunnelStage(val wire: String) {
    DISCONNECTED("disconnected"),
    CONNECTING("connecting"),
    VALIDATING("validating"),
    CONNECTED("connected"),
    DISCONNECTING("disconnecting"),
    FAILED("failed");

    val isIdle: Boolean get() = this == DISCONNECTED || this == FAILED
}

/**
 * Point-in-time snapshot of the active VPN tunnel.
 */
data class TunnelSnapshot(
    val stage: TunnelStage,
    val gateway: String?,
    val connectedAtMillis: Long,
    val message: String?,
) {
    companion object {
        val DISCONNECTED = TunnelSnapshot(
            stage = TunnelStage.DISCONNECTED,
            gateway = null,
            connectedAtMillis = 0L,
            message = null,
        )
    }
}
