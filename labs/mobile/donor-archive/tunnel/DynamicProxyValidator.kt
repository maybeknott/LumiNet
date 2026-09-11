package com.luminet.android.tunnel

import java.util.concurrent.ConcurrentHashMap

enum class AndroidProxyProto {
    HTTP,
    HTTPS,
    SOCKS4,
    SOCKS5
}

enum class AndroidProxyAnon {
    TRANSPARENT,
    ANONYMOUS,
    ELITE
}

data class AndroidProxyRecord(
    val host: String,
    val port: Int,
    val protocol: AndroidProxyProto,
    val isAlive: Boolean,
    val latencyMs: Long,
    val anonymity: AndroidProxyAnon,
    val lastCheckedMs: Long
)

class DynamicProxyValidator(val timeoutMs: Long = 5000) {
    private val pool = ConcurrentHashMap<String, AndroidProxyRecord>()

    fun craftSocks5Probe(): ByteArray = byteArrayOf(0x05, 0x01, 0x00)

    fun craftHttpProbe(host: String): String =
        "GET http://$host/generate_204 HTTP/1.1\r\nHost: $host\r\nConnection: close\r\n\r\n"

    fun verifySocks5Response(resp: ByteArray): Boolean =
        resp.size >= 2 && resp[0] == 0x05.toByte() && resp[1] == 0x00.toByte()

    fun determineAnonymity(headers: Map<String, String>, myIp: String): AndroidProxyAnon {
        val forwardKeys = listOf("x-forwarded-for", "via", "x-real-ip", "forwarded")
        var hasForwarding = false

        for ((k, v) in headers) {
            if (forwardKeys.contains(k.lowercase())) {
                hasForwarding = true
                if (v.contains(myIp)) return AndroidProxyAnon.TRANSPARENT
            }
        }

        return if (hasForwarding) AndroidProxyAnon.ANONYMOUS else AndroidProxyAnon.ELITE
    }

    fun recordProbe(
        host: String,
        port: Int,
        proto: AndroidProxyProto,
        isAlive: Boolean,
        latencyMs: Long,
        anon: AndroidProxyAnon,
        nowMs: Long
    ) {
        val key = "$host:$port"
        pool[key] = AndroidProxyRecord(host, port, proto, isAlive, latencyMs, anon, nowMs)
    }

    fun getHealthyProxies(maxLatencyMs: Long): List<AndroidProxyRecord> {
        return pool.values
            .filter { it.isAlive && it.latencyMs <= maxLatencyMs }
            .sortedBy { it.latencyMs }
    }
}
