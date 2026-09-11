package com.luminet.android.tunnel

class TunRouteSynchronizer(
    val tunMtu: Int = 1400
) {
    private val bypassPrefixes = mutableListOf(
        "10.", "127.", "169.254.", "172.16.", "192.168.", "224.", "fe80:", "::1"
    )

    fun addBypassPrefix(prefix: String) {
        if (!bypassPrefixes.contains(prefix)) bypassPrefixes.add(prefix)
    }

    fun shouldBypass(ip: String): Boolean {
        val trimmed = ip.trim()
        return bypassPrefixes.any { trimmed.startsWith(it) }
    }

    fun calculateClampedMss(isIpv6: Boolean): Int {
        val overhead = if (isIpv6) 60 else 40
        return (tunMtu - overhead).coerceAtLeast(1200)
    }
}
