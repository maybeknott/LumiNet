package com.luminet.android.tunnel

data class AndroidClashNode(
    val name: String,
    val server: String,
    val port: Int,
    val type: String,
    val uuid: String
)

data class AndroidClashGroup(
    val name: String,
    val type: String,
    val proxies: List<String>
)

class ClashProviderSynthesizer(val mixedPort: Int = 7890) {
    private val nodes = mutableListOf<AndroidClashNode>()
    private val groups = mutableListOf<AndroidClashGroup>()

    fun addNode(node: AndroidClashNode) {
        nodes.add(node)
    }

    fun addGroup(group: AndroidClashGroup) {
        groups.add(group)
    }

    fun synthesizeYaml(): String {
        val sb = StringBuilder()
        sb.append("mixed-port: ").append(mixedPort).append("\n")
        sb.append("mode: rule\n\nproxies:\n")
        for (n in nodes) {
            sb.append("  - name: \"").append(n.name).append("\"\n")
            sb.append("    type: ").append(n.type).append("\n")
            sb.append("    server: ").append(n.server).append("\n")
            sb.append("    port: ").append(n.port).append("\n")
            sb.append("    uuid: ").append(n.uuid).append("\n")
        }
        sb.append("\nproxy-groups:\n")
        for (g in groups) {
            sb.append("  - name: \"").append(g.name).append("\"\n")
            sb.append("    type: ").append(g.type).append("\n")
            sb.append("    proxies:\n")
            for (p in g.proxies) {
                sb.append("      - \"").append(p).append("\"\n")
            }
        }
        return sb.toString()
    }
}
