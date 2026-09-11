package com.luminet.android.tunnel

data class AndroidUpstreamNode(
    val id: String,
    val protocol: String,
    val endpoint: String,
    var latencyMs: Long,
    var isAlive: Boolean
)

class UpstreamMatrix {
    private val nodes = mutableMapOf<String, AndroidUpstreamNode>()

    fun register(node: AndroidUpstreamNode) {
        nodes[node.id] = node
    }

    fun update(id: String, isAlive: Boolean, latencyMs: Long) {
        nodes[id]?.let {
            it.isAlive = isAlive
            it.latencyMs = latencyMs
        }
    }

    fun selectBest(): AndroidUpstreamNode? {
        return nodes.values
            .filter { it.isAlive }
            .minByOrNull { it.latencyMs }
    }
}
