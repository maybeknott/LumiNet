package com.luminet.android.tunnel

import org.json.JSONArray
import org.json.JSONObject
import java.net.URI
import java.net.URLDecoder

/**
 * Multi-protocol proxy parser and sing-box client configuration generator.
 *
 */
data class SingboxOutboundNode(
    val type: String,
    val tag: String,
    val server: String,
    val port: Int,
    val uuid: String = "",
    val password: String = "",
    val security: String = "",
    val network: String = "tcp",
    val tls: Boolean = false,
    val sni: String = "",
    val realityPubKey: String = "",
    val realityShortId: String = ""
)

data class SingboxGeneratorOptions(
    val listen: String = "127.0.0.1",
    val mixedPort: Int = 2080,
    val tunEnabled: Boolean = true,
    val tunMtu: Int = 9000,
    val autoUrlTest: Boolean = true,
    val testUrl: String = "https://www.gstatic.com/generate_204"
)

class SingboxConfigGenerator {

    fun parseSubscription(raw: String): List<SingboxOutboundNode> {
        val lines = raw.lines()
        val nodes = mutableListOf<SingboxOutboundNode>()
        val seenTags = mutableMapOf<String, Int>()

        for (line in lines) {
            val trimmed = line.trim()
            if (trimmed.isEmpty() || trimmed.startsWith("#") || trimmed.startsWith("//")) {
                continue
            }

            val node = parseLine(trimmed) ?: continue
            var tag = node.tag.ifEmpty { node.type }
            val baseTag = tag
            var count = 1
            while (seenTags.containsKey(tag)) {
                tag = "$baseTag-$count"
                count++
            }
            seenTags[tag] = 1

            nodes.add(node.copy(tag = tag))
        }

        return nodes
    }

    private fun parseLine(line: String): SingboxOutboundNode? {
        return when {
            line.startsWith("vless://") -> parseVless(line)
            line.startsWith("trojan://") -> parseTrojan(line)
            line.startsWith("ss://") -> parseShadowsocks(line)
            else -> null
        }
    }

    private fun parseVless(url: String): SingboxOutboundNode? {
        try {
            val raw = url.removePrefix("vless://")
            val (main, fragment) = if (raw.contains("#")) {
                val parts = raw.split("#", limit = 2)
                Pair(parts[0], URLDecoder.decode(parts[1], "UTF-8"))
            } else {
                Pair(raw, "vless")
            }

            val (userinfo, hostinfo) = main.split("@", limit = 2)
            val (hostport, query) = if (hostinfo.contains("?")) {
                hostinfo.split("?", limit = 2)
            } else {
                Pair(hostinfo, "")
            }

            val parts = hostport.split(":")
            val server = parts[0]
            val port = parts[1].toInt()

            val queryParams = parseQuery(query)
            val sec = queryParams["security"] ?: "tls"
            val isReality = sec == "reality"
            val isTls = sec == "tls" || isReality

            return SingboxOutboundNode(
                type = "vless",
                tag = fragment,
                server = server,
                port = port,
                uuid = URLDecoder.decode(userinfo, "UTF-8"),
                security = sec,
                tls = isTls,
                sni = queryParams["sni"] ?: queryParams["host"] ?: "",
                realityPubKey = queryParams["pbk"] ?: "",
                realityShortId = queryParams["sid"] ?: ""
            )
        } catch (_: Exception) {
            return null
        }
    }

    private fun parseTrojan(url: String): SingboxOutboundNode? {
        try {
            val raw = url.removePrefix("trojan://")
            val (main, fragment) = if (raw.contains("#")) {
                val parts = raw.split("#", limit = 2)
                Pair(parts[0], URLDecoder.decode(parts[1], "UTF-8"))
            } else {
                Pair(raw, "trojan")
            }

            val (userinfo, hostinfo) = main.split("@", limit = 2)
            val (hostport, query) = if (hostinfo.contains("?")) {
                hostinfo.split("?", limit = 2)
            } else {
                Pair(hostinfo, "")
            }

            val parts = hostport.split(":")
            val server = parts[0]
            val port = parts[1].toInt()
            val queryParams = parseQuery(query)

            return SingboxOutboundNode(
                type = "trojan",
                tag = fragment,
                server = server,
                port = port,
                password = URLDecoder.decode(userinfo, "UTF-8"),
                tls = true,
                sni = queryParams["sni"] ?: queryParams["host"] ?: ""
            )
        } catch (_: Exception) {
            return null
        }
    }

    private fun parseShadowsocks(url: String): SingboxOutboundNode? {
        try {
            val raw = url.removePrefix("ss://")
            val (main, fragment) = if (raw.contains("#")) {
                val parts = raw.split("#", limit = 2)
                Pair(parts[0], URLDecoder.decode(parts[1], "UTF-8"))
            } else {
                Pair(raw, "ss")
            }

            if (main.contains("@")) {
                val (userinfo, hostinfo) = main.split("@", limit = 2)
                val parts = hostinfo.split(":")
                return SingboxOutboundNode(
                    type = "shadowsocks",
                    tag = fragment,
                    server = parts[0],
                    port = parts[1].toInt(),
                    password = userinfo
                )
            }
            return null
        } catch (_: Exception) {
            return null
        }
    }

    private fun parseQuery(query: String): Map<String, String> {
        val map = mutableMapOf<String, String>()
        if (query.isBlank()) return map
        for (part in query.split("&")) {
            val pair = part.split("=", limit = 2)
            if (pair.size == 2) {
                map[pair[0]] = URLDecoder.decode(pair[1], "UTF-8")
            }
        }
        return map
    }

    fun generateConfigJson(nodes: List<SingboxOutboundNode>, opts: SingboxGeneratorOptions = SingboxGeneratorOptions()): String {
        val root = JSONObject()

        // Log
        val log = JSONObject().apply {
            put("level", "info")
            put("timestamp", true)
        }
        root.put("log", log)

        // Inbounds
        val inbounds = JSONArray()
        if (opts.tunEnabled) {
            val tun = JSONObject().apply {
                put("type", "tun")
                put("tag", "tun-in")
                put("address", JSONArray(listOf("172.19.0.1/30", "fdfe:dcba:9876::1/126")))
                put("mtu", opts.tunMtu)
                put("auto_route", true)
                put("strict_route", true)
                put("stack", "system")
                put("dns_mode", "hijack")
            }
            inbounds.put(tun)
        }

        val mixed = JSONObject().apply {
            put("type", "mixed")
            put("tag", "mixed-in")
            put("listen", opts.listen)
            put("listen_port", opts.mixedPort)
            put("set_system_proxy", false)
        }
        inbounds.put(mixed)
        root.put("inbounds", inbounds)

        // Outbounds
        val outbounds = JSONArray()
        val tags = nodes.map { it.tag }

        val selectorOutbounds = mutableListOf<String>()
        if (opts.autoUrlTest && tags.isNotEmpty()) {
            selectorOutbounds.add("auto")
        }
        selectorOutbounds.addAll(tags)
        selectorOutbounds.add("direct")

        val selector = JSONObject().apply {
            put("type", "selector")
            put("tag", "select")
            put("outbounds", JSONArray(selectorOutbounds))
            put("default", if (opts.autoUrlTest && tags.isNotEmpty()) "auto" else "select")
        }
        outbounds.put(selector)

        if (opts.autoUrlTest && tags.isNotEmpty()) {
            val urltest = JSONObject().apply {
                put("type", "urltest")
                put("tag", "auto")
                put("outbounds", JSONArray(tags))
                put("url", opts.testUrl)
                put("interval", "3m")
                put("tolerance", 50)
            }
            outbounds.put(urltest)
        }

        for (n in nodes) {
            val ob = JSONObject().apply {
                put("type", n.type)
                put("tag", n.tag)
                put("server", n.server)
                put("server_port", n.port)
                if (n.uuid.isNotEmpty()) put("uuid", n.uuid)
                if (n.password.isNotEmpty()) put("password", n.password)
                if (n.tls) {
                    val tls = JSONObject().apply {
                        put("enabled", true)
                        if (n.sni.isNotEmpty()) put("server_name", n.sni)
                        if (n.realityPubKey.isNotEmpty()) {
                            val reality = JSONObject().apply {
                                put("enabled", true)
                                put("public_key", n.realityPubKey)
                                put("short_id", n.realityShortId)
                            }
                            put("reality", reality)
                        }
                    }
                    put("tls", tls)
                }
            }
            outbounds.put(ob)
        }

        outbounds.put(JSONObject(mapOf("type" to "direct", "tag" to "direct")))
        outbounds.put(JSONObject(mapOf("type" to "block", "tag" to "block")))
        outbounds.put(JSONObject(mapOf("type" to "dns", "tag" to "dns-out")))
        root.put("outbounds", outbounds)

        return root.toString(2)
    }
}
