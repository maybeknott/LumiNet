package com.luminet.android.tunnel

import java.nio.ByteBuffer
import java.util.concurrent.ConcurrentHashMap
import java.util.concurrent.atomic.AtomicInteger
import java.util.concurrent.atomic.AtomicLong

enum class ProxyProtocolVersion {
    NONE,
    V1,
    V2
}

data class RelayEndpoint(
    val targetHost: String,
    val targetPort: Int,
    val weight: Int = 1,
    var isAlive: Boolean = true,
    var activeConnections: Int = 0,
    var totalBytesRelayed: Long = 0L
)

class ZeroCopyNetworkRelay(
    val listenPort: Int,
    val proxyProtocol: ProxyProtocolVersion
) {
    private val endpoints = mutableListOf<RelayEndpoint>()
    private val endpointIndex = AtomicInteger(0)
    private val sessions = ConcurrentHashMap<Long, RelayEndpoint>()
    private val nextSessionId = AtomicLong(1L)

    fun addEndpoint(endpoint: RelayEndpoint) {
        endpoints.add(endpoint)
    }

    fun openSession(): Pair<Long, RelayEndpoint>? {
        val healthy = endpoints.filter { it.isAlive }
        if (healthy.isEmpty()) return null

        val idx = Math.floorMod(endpointIndex.getAndIncrement(), healthy.size)
        val chosen = healthy[idx]
        chosen.activeConnections++

        val sid = nextSessionId.getAndIncrement()
        sessions[sid] = chosen
        return Pair(sid, chosen)
    }

    fun closeSession(sessionId: Long, bytesRelayed: Long) {
        sessions.remove(sessionId)?.let { ep ->
            if (ep.activeConnections > 0) ep.activeConnections--
            ep.totalBytesRelayed += bytesRelayed
        }
    }

    fun generateProxyHeader(clientIp: String, clientPort: Int, serverIp: String, serverPort: Int): ByteArray {
        return when (proxyProtocol) {
            ProxyProtocolVersion.V1 -> {
                val family = if (clientIp.contains(":")) "TCP6" else "TCP4"
                "PROXY $family $clientIp $serverIp $clientPort $serverPort\r\n".toByteArray(Charsets.US_ASCII)
            }
            ProxyProtocolVersion.V2 -> {
                val buf = ByteBuffer.allocate(16)
                val sig = byteArrayOf(0x0D, 0x0A, 0x0D, 0x0A, 0x00, 0x0D, 0x0A, 0x51, 0x55, 0x49, 0x54, 0x0A, 0x21, 0x11, 0x00, 0x00)
                buf.put(sig)
                buf.array()
            }
            ProxyProtocolVersion.NONE -> ByteArray(0)
        }
    }
}
