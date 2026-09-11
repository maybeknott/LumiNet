// Copyright 2024-2026 LumiNet Authors. All Rights Reserved.
package com.luminet.android.tunnel

data class OutboundCandidate(
    val nodeId: String,
    val protocol: String,
    val endpoint: String,
    var ewmaLatencyMs: Double = 0.0,
    var totalProbes: Long = 0
)

class LatencyRaceSelector {
    private val nodes = mutableMapOf<String, OutboundCandidate>()
    private val lock = Any()

    fun registerNode(id: String, protocol: String, endpoint: String) = synchronized(lock) {
        nodes[id] = OutboundCandidate(id, protocol, endpoint)
    }

    fun recordProbe(id: String, latencyMs: Double) = synchronized(lock) {
        val n = nodes[id] ?: return
        n.totalProbes++
        n.ewmaLatencyMs = if (n.ewmaLatencyMs == 0.0) latencyMs else 0.7 * n.ewmaLatencyMs + 0.3 * latencyMs
    }

    fun selectFastest(): OutboundCandidate? = synchronized(lock) {
        nodes.values.filter { it.ewmaLatencyMs > 0.0 }.minByOrNull { it.ewmaLatencyMs }
    }
}
