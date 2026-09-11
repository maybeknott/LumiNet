// Copyright 2024-2026 LumiNet Authors. All Rights Reserved.
package com.luminet.android.tunnel

data class MeshLinkMetric(
    val directRttMs: Double,
    val packetLoss: Double,
    val hops: Int,
    val cost: Double
)

class MeshPeerTable {
    private val peers = mutableMapOf<String, MutableMap<String, MeshLinkMetric>>()
    private val lock = Any()

    fun recordLink(source: String, dest: String, rtt: Double, loss: Double, hops: Int) = synchronized(lock) {
        val cost = (rtt * 0.7) + (loss * 350.0) + (hops * 15.0)
        peers.getOrPut(source) { mutableMapOf() }[dest] = MeshLinkMetric(rtt, loss, hops, cost)
    }

    fun findBestRoute(source: String, dest: String): Pair<String, Double>? = synchronized(lock) {
        val adj = peers[source] ?: return null
        var bestNextHop: String? = null
        var minCost = Double.MAX_VALUE

        adj[dest]?.let {
            bestNextHop = dest
            minCost = it.cost
        }

        for ((intermediate, link1) in adj) {
            if (intermediate == dest) continue
            val link2 = peers[intermediate]?.get(dest) ?: continue
            val totalCost = link1.cost + link2.cost
            if (totalCost < minCost) {
                minCost = totalCost
                bestNextHop = intermediate
            }
        }

        bestNextHop?.let { Pair(it, minCost) }
    }
}
