// Copyright 2024-2026 LumiNet Authors. All Rights Reserved.
package com.luminet.android.tunnel

data class CdnCandidate(
    val ip: String,
    val sni: String,
    val port: Int = 443,
    var rttEmaMs: Double = 0.0,
    var successCount: Long = 0,
    var failureCount: Long = 0,
    var quarantinedUntilMs: Long = 0
) {
    fun isQuarantined(nowMs: Long = System.currentTimeMillis()): Boolean = nowMs < quarantinedUntilMs

    fun recordSuccess(rttMs: Double) {
        successCount++
        rttEmaMs = if (rttEmaMs == 0.0) rttMs else 0.8 * rttEmaMs + 0.2 * rttMs
    }

    fun recordFailure(quarantineDurationMs: Long = 60_000, nowMs: Long = System.currentTimeMillis()) {
        failureCount++
        if (failureCount % 3L == 0L) {
            quarantinedUntilMs = nowMs + quarantineDurationMs
        }
    }
}

class CdnFrontPool(
    private val quarantineDurationMs: Long = 60_000,
    private val maxCapacity: Int = 100
) {
    private val candidates = mutableListOf<CdnCandidate>()
    private val lock = Any()

    fun addCandidate(ip: String, sni: String, port: Int = 443): Boolean = synchronized(lock) {
        if (candidates.any { it.ip == ip && it.sni == sni && it.port == port }) return true
        if (candidates.size >= maxCapacity) return false
        candidates.add(CdnCandidate(ip, sni, port))
        true
    }

    fun selectBest(nowMs: Long = System.currentTimeMillis()): CdnCandidate? = synchronized(lock) {
        candidates.filter { !it.isQuarantined(nowMs) }
            .minByOrNull { if (it.rttEmaMs == 0.0) 50.0 else it.rttEmaMs }
    }
}
