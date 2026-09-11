package com.luminet.android.tunnel

data class AggregatedNode(
    val id: String,
    val protocol: String,
    val host: String,
    val port: Int,
    var score: Double = 50.0,
    var latencyMs: Int = 200,
    var successCount: Int = 1,
    var failureCount: Int = 0,
    val tags: MutableList<String> = mutableListOf("public_pool"),
    var lastSeen: Long = 0
)

class NodePoolAggregator {
    private val nodes = HashMap<String, AggregatedNode>()

    fun ingestRawEntries(entries: List<String>, timestamp: Long): Int {
        var count = 0
        for (raw in entries) {
            val node = parseRawLine(raw, timestamp)
            if (node != null) {
                val key = "${node.protocol}:${node.host}:${node.port}"
                val existing = nodes[key]
                if (existing != null) {
                    existing.lastSeen = timestamp
                    for (tag in node.tags) {
                        if (!existing.tags.contains(tag)) {
                            existing.tags.add(tag)
                        }
                    }
                } else {
                    nodes[key] = node
                }
                count++
            }
        }
        return count
    }

    fun updateHealth(id: String, latencyMs: Int, success: Boolean): Boolean {
        val node = nodes[id] ?: return false
        if (success) {
            node.successCount++
            node.latencyMs = (node.latencyMs * 3 + latencyMs) / 4
            val latScore = (1000.0 / node.latencyMs.coerceAtLeast(10)).coerceAtMost(100.0)
            val rel = node.successCount.toDouble() / (node.successCount + node.failureCount)
            node.score = (latScore * 0.4) + (rel * 60.0)
        } else {
            node.failureCount++
            val rel = node.successCount.toDouble() / (node.successCount + node.failureCount)
            if (node.score > rel * 60.0) {
                node.score = rel * 60.0
            }
        }
        return true
    }

    fun rankNodes(minScore: Double): List<AggregatedNode> {
        return nodes.values
            .filter { it.score >= minScore }
            .sortedByDescending { it.score }
    }

    private fun parseRawLine(raw: String, timestamp: Long): AggregatedNode? {
        val trimmed = raw.trim()
        if (trimmed.isEmpty() || trimmed.startsWith("#")) {
            return null
        }

        val idx = trimmed.indexOf("://")
        if (idx == -1) return null

        val proto = trimmed.substring(0, idx).lowercase()
        val rem = trimmed.substring(idx + 3)

        val parts = rem.split("@")
        val hostPort = if (parts.size > 1) parts[1] else parts[0]
        val hostSplit = hostPort.split(":")
        if (hostSplit.size < 2) return null

        val host = hostSplit[0]
        val portStr = hostSplit[1].split('/', '?', '#')[0]
        val port = portStr.toIntOrNull() ?: 443

        return AggregatedNode(
            id = "$proto:$host:$port",
            protocol = proto,
            host = host,
            port = port,
            lastSeen = timestamp
        )
    }
}
