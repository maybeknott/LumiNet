package com.luminet.android.tunnel

data class AndroidDohEndpoint(
    val url: String,
    val host: String,
    val tier: Int,
    var isHealthy: Boolean = true,
    var consecutiveFails: Int = 0,
    var latencyMs: Long = 30L
)

class DohFallbackHierarchy {
    val endpoints = mutableListOf<AndroidDohEndpoint>()

    init {
        endpoints.add(AndroidDohEndpoint("https://1.1.1.1/dns-query", "cloudflare-dns.com", 1, true, 0, 25))
        endpoints.add(AndroidDohEndpoint("https://dns.google/dns-query", "dns.google", 1, true, 0, 35))
        endpoints.add(AndroidDohEndpoint("https://doh.opendns.com/dns-query", "doh.opendns.com", 2, true, 0, 60))
    }

    fun recordFailure(url: String) {
        val ep = endpoints.find { it.url == url } ?: return
        ep.consecutiveFails++
        if (ep.consecutiveFails >= 3) {
            ep.isHealthy = false
        }
    }

    fun selectActive(): AndroidDohEndpoint? {
        val healthy = endpoints.filter { it.isHealthy }
        if (healthy.isEmpty()) return endpoints.firstOrNull()

        return healthy.sortedWith(compareBy({ it.tier }, { it.latencyMs })).firstOrNull()
    }
}
