// Copyright 2024-2026 LumiNet Authors. All Rights Reserved.
package com.luminet.android.tunnel

data class DnsCandidateRecord(
    val ip: String,
    var latencyMs: Double = 0.0,
    var isResponsive: Boolean = false,
    var isPoisoned: Boolean = false
)

class SubnetDnsScanner(private val expectedIp: String = "93.184.216.34") {
    private val servers = mutableMapOf<String, DnsCandidateRecord>()
    private val lock = Any()

    fun recordProbe(ip: String, latencyMs: Double, resolvedIp: String?, hasError: Boolean) = synchronized(lock) {
        if (hasError || resolvedIp == null) {
            servers[ip] = DnsCandidateRecord(ip, 0.0, false, false)
            return
        }
        val poisoned = resolvedIp != expectedIp
        servers[ip] = DnsCandidateRecord(ip, latencyMs, true, poisoned)
    }

    fun selectCleanFastest(): DnsCandidateRecord? = synchronized(lock) {
        servers.values.filter { it.isResponsive && !it.isPoisoned }.minByOrNull { it.latencyMs }
    }
}
