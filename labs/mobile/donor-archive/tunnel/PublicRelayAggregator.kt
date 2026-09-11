package com.luminet.android.tunnel

data class AndroidRelayNode(
    val nodeId: String,
    val protocol: String,
    val host: String,
    val port: Int,
    val countryCode: String,
    var pingMs: Int,
    var isAlive: Boolean = true
)

class PublicRelayAggregator {
    private val relays = mutableMapOf<String, AndroidRelayNode>()

    fun ingestNode(node: AndroidRelayNode) {
        relays[node.nodeId] = node
    }

    fun updateHealth(nodeId: String, pingMs: Int, isAlive: Boolean) {
        val n = relays[nodeId] ?: return
        n.pingMs = pingMs
        n.isAlive = isAlive
    }

    fun queryRelays(country: String?, proto: String?, maxResults: Int): List<AndroidRelayNode> {
        return relays.values
            .filter { it.isAlive }
            .filter { country == null || it.countryCode == country }
            .filter { proto == null || it.protocol == proto }
            .sortedBy { it.pingMs }
            .take(maxResults)
    }

    fun totalCount(): Int = relays.size
}
