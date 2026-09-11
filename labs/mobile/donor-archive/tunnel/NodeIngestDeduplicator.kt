package com.luminet.android.tunnel

data class AndroidNodeEndpointKey(
    val host: String,
    val port: Int,
    val protocol: String
)

data class AndroidScrapedNode(
    val host: String,
    val port: Int,
    val protocol: String,
    val source: String,
    val pingMs: Long,
    val isAlive: Boolean
)

class NodeIngestDeduplicator {
    private val seenEndpoints = mutableSetOf<AndroidNodeEndpointKey>()
    private val uniqueNodes = mutableListOf<AndroidScrapedNode>()
    private val sourceStats = mutableMapOf<String, Int>()

    fun ingestNode(node: AndroidScrapedNode): Boolean {
        val key = AndroidNodeEndpointKey(
            host = node.host.trim().lowercase(),
            port = node.port,
            protocol = node.protocol.trim().lowercase()
        )

        return if (seenEndpoints.add(key)) {
            sourceStats[node.source] = (sourceStats[node.source] ?: 0) + 1
            uniqueNodes.add(node)
            true
        } else {
            false
        }
    }

    fun getRankedNodes(): List<AndroidScrapedNode> {
        return uniqueNodes
            .filter { it.isAlive }
            .sortedBy { it.pingMs }
    }

    fun totalUnique(): Int = uniqueNodes.size

    fun countForSource(source: String): Int = sourceStats[source] ?: 0
}
