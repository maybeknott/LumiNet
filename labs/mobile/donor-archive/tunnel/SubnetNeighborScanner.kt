package com.luminet.android.tunnel

data class NeighborPeer(
    val ip: String,
    val port: Int,
    val rttMs: Long,
    val isGateway: Boolean
)

class SubnetNeighborScanner {
    fun scan(baseIp: String, port: Int = 443, count: Int = 10): List<NeighborPeer> {
        val peers = mutableListOf<NeighborPeer>()
        for (i in 1..count.coerceAtMost(254)) {
            val ip = "$baseIp.$i"
            val rtt = 10L + (i * 7L) % 90L
            val isGw = (i == 1)
            peers.add(NeighborPeer(ip, port, rtt, isGw))
        }
        return peers.sortedBy { it.rttMs }
    }
}
