package com.luminet.android.tunnel

import java.net.URI
import java.util.Base64
import java.util.concurrent.CopyOnWriteArrayList

data class AndroidProxyNode(
    val id: String,
    val protocol: String,
    val server: String,
    val port: Int,
    val credentials: String,
    val transport: String,
    val sni: String?,
    val tag: String
)

class CommunityFeedParser {
    val nodes = CopyOnWriteArrayList<AndroidProxyNode>()

    fun decodeFeed(raw: String): String {
        val trimmed = raw.trim()
        if (trimmed.startsWith("vless://") || trimmed.startsWith("vmess://") ||
            trimmed.startsWith("trojan://") || trimmed.startsWith("ss://")) {
            return trimmed
        }
        val clean = trimmed.replace(Regex("\\s+"), "")
        return try {
            String(Base64.getDecoder().decode(clean), Charsets.UTF_8)
        } catch (e: Exception) {
            try {
                String(Base64.getUrlDecoder().decode(clean), Charsets.UTF_8)
            } catch (e2: Exception) {
                ""
            }
        }
    }

    fun parseUri(uriStr: String): AndroidProxyNode? {
        return try {
            val uri = URI(uriStr.trim())
            val scheme = uri.scheme?.lowercase() ?: return null
            val server = uri.host ?: return null
            val port = if (uri.port != -1) uri.port else 443
            val userInfo = uri.userInfo ?: ""
            val query = uri.query ?: ""
            val tag = uri.fragment ?: "$scheme-node"

            val queryMap = query.split("&").mapNotNull {
                val kv = it.split("=", limit = 2)
                if (kv.size == 2) kv[0] to kv[1] else null
            }.toMap()

            when (scheme) {
                "vless", "vmess" -> {
                    AndroidProxyNode(
                        id = "$scheme-$server:$port",
                        protocol = scheme,
                        server = server,
                        port = port,
                        credentials = userInfo,
                        transport = queryMap["type"] ?: "tcp",
                        sni = queryMap["sni"],
                        tag = tag
                    )
                }
                "trojan" -> {
                    AndroidProxyNode(
                        id = "trojan-$server:$port",
                        protocol = "trojan",
                        server = server,
                        port = port,
                        credentials = userInfo,
                        transport = "tcp",
                        sni = queryMap["sni"],
                        tag = tag
                    )
                }
                "ss" -> {
                    AndroidProxyNode(
                        id = "ss-$server:$port",
                        protocol = "shadowsocks",
                        server = server,
                        port = port,
                        credentials = userInfo,
                        transport = "tcp",
                        sni = null,
                        tag = tag
                    )
                }
                else -> null
            }
        } catch (e: Exception) {
            null
        }
    }

    fun parseFeedContent(content: String): Int {
        val decoded = decodeFeed(content)
        var added = 0
        for (line in decoded.lines()) {
            val trimmed = line.trim()
            if (trimmed.isNotEmpty()) {
                val node = parseUri(trimmed)
                if (node != null) {
                    nodes.add(node)
                    added++
                }
            }
        }
        return added
    }

    fun deduplicate(): Int {
        val seen = mutableSetOf<String>()
        val initial = nodes.size
        val unique = mutableListOf<AndroidProxyNode>()

        for (node in nodes) {
            val key = "${node.protocol}:${node.server}:${node.port}"
            if (seen.add(key)) {
                unique.add(node)
            }
        }
        nodes.clear()
        nodes.addAll(unique)
        return initial - unique.size
    }
}
