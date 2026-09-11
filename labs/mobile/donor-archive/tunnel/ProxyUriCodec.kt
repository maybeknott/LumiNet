package com.luminet.android.tunnel

data class CanonicalProxyNode(
    val protocol: String,
    val uuidOrPassword: String,
    val address: String,
    val port: Int,
    val remark: String,
    val params: Map<String, String>
)

class ProxyUriCodec {
    fun parse(rawUri: String): CanonicalProxyNode? {
        try {
            val trimmed = rawUri.trim()
            val schemeIdx = trimmed.indexOf("://")
            if (schemeIdx < 0) return null
            val proto = trimmed.substring(0, schemeIdx).lowercase()
            var rest = trimmed.substring(schemeIdx + 3)

            val remark = if (rest.contains("#")) {
                val p = rest.split("#", limit = 2)
                rest = p[0]
                p[1]
            } else ""

            val (authAndHost, query) = if (rest.contains("?")) {
                val p = rest.split("?", limit = 2)
                Pair(p[0], p[1])
            } else Pair(rest, "")

            val credAndHost = authAndHost.split("@", limit = 2)
            if (credAndHost.size < 2) return null
            val cred = credAndHost[0]
            val hostPort = credAndHost[1].split(":", limit = 2)
            val host = hostPort[0]
            val port = if (hostPort.size > 1) hostPort[1].toInt() else 443

            val params = mutableMapOf<String, String>()
            if (query.isNotEmpty()) {
                query.split("&").forEach { kv ->
                    val pair = kv.split("=", limit = 2)
                    if (pair.isNotEmpty() && pair[0].isNotEmpty()) {
                        params[pair[0]] = if (pair.size > 1) pair[1] else ""
                    }
                }
            }

            return CanonicalProxyNode(proto, cred, host, port, remark, params)
        } catch (e: Exception) {
            return null
        }
    }

    fun serialize(node: CanonicalProxyNode): String {
        val q = node.params.entries.sortedBy { it.key }.joinToString("&") { "${it.key}=${it.value}" }
        val qStr = if (q.isNotEmpty()) "?$q" else ""
        val rStr = if (node.remark.isNotEmpty()) "#${node.remark}" else ""
        return "${node.protocol}://${node.uuidOrPassword}@${node.address}:${node.port}$qStr$rStr"
    }
}
