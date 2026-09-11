package com.luminet.android.tunnel

import android.util.Base64
import java.net.URI

enum class AndroidProxyType {
    VMESS, SHADOWSOCKS, TROJAN, VLESS, UNKNOWN
}

data class ExtractedProxyNode(
    val nodeType: AndroidProxyType,
    val address: String,
    val port: Int,
    val credential: String,
    val remark: String
)

class SubscriptionNodeExtractor {
    fun decodeSubscription(base64Content: String): List<ExtractedProxyNode> {
        val clean = base64Content.replace("\r", "").replace("\n", "").trim()
        val decoded = try {
            val bytes = java.util.Base64.getDecoder().decode(clean)
            String(bytes, Charsets.UTF_8)
        } catch (e: Exception) {
            try {
                val bytes = java.util.Base64.getUrlDecoder().decode(clean)
                String(bytes, Charsets.UTF_8)
            } catch (e2: Exception) {
                return emptyList()
            }
        }

        val lines = decoded.split("\n").map { it.trim() }.filter { it.isNotEmpty() }
        val nodes = mutableListOf<ExtractedProxyNode>()

        for (line in lines) {
            when {
                line.startsWith("trojan://") -> parseTrojan(line)?.let { nodes.add(it) }
                line.startsWith("ss://") -> parseShadowsocks(line)?.let { nodes.add(it) }
                line.startsWith("vless://") -> parseVless(line)?.let { nodes.add(it) }
                line.startsWith("vmess://") -> parseVmess(line)?.let { nodes.add(it) }
            }
        }
        return nodes
    }

    private fun parseTrojan(uriStr: String): ExtractedProxyNode? = try {
        val uri = URI(uriStr)
        ExtractedProxyNode(
            nodeType = AndroidProxyType.TROJAN,
            address = uri.host ?: "",
            port = if (uri.port > 0) uri.port else 443,
            credential = uri.userInfo ?: "",
            remark = uri.fragment ?: ""
        )
    } catch (e: Exception) {
        null
    }

    private fun parseVless(uriStr: String): ExtractedProxyNode? = try {
        val uri = URI(uriStr)
        ExtractedProxyNode(
            nodeType = AndroidProxyType.VLESS,
            address = uri.host ?: "",
            port = if (uri.port > 0) uri.port else 443,
            credential = uri.userInfo ?: "",
            remark = uri.fragment ?: ""
        )
    } catch (e: Exception) {
        null
    }

    private fun parseShadowsocks(uriStr: String): ExtractedProxyNode? = try {
        val withoutScheme = uriStr.removePrefix("ss://")
        val fragmentParts = withoutScheme.split("#", limit = 2)
        val mainPart = fragmentParts[0]
        val remark = if (fragmentParts.size > 1) fragmentParts[1] else ""

        if (mainPart.contains("@")) {
            val atParts = mainPart.split("@", limit = 2)
            val cred = atParts[0]
            val hostPort = atParts[1].split(":", limit = 2)
            ExtractedProxyNode(
                nodeType = AndroidProxyType.SHADOWSOCKS,
                address = hostPort[0],
                port = if (hostPort.size > 1) hostPort[1].toIntOrNull() ?: 8388 else 8388,
                credential = cred,
                remark = remark
            )
        } else {
            null
        }
    } catch (e: Exception) {
        null
    }

    private fun parseVmess(uriStr: String): ExtractedProxyNode? = try {
        val b64 = uriStr.removePrefix("vmess://").trim()
        val decodedJson = String(java.util.Base64.getDecoder().decode(b64), Charsets.UTF_8)
        // Minimal json parser for add, port, id, ps
        val host = extractJsonField(decodedJson, "add") ?: "unknown"
        val port = extractJsonField(decodedJson, "port")?.toIntOrNull() ?: 443
        val id = extractJsonField(decodedJson, "id") ?: ""
        val ps = extractJsonField(decodedJson, "ps") ?: ""
        ExtractedProxyNode(
            nodeType = AndroidProxyType.VMESS,
            address = host,
            port = port,
            credential = id,
            remark = ps
        )
    } catch (e: Exception) {
        null
    }

    private fun extractJsonField(json: String, key: String): String? {
        val pattern = "\"$key\"\\s*:\\s*\"?([^\"\\s,{}]+)\"?".toRegex()
        return pattern.find(json)?.groupValues?.get(1)
    }
}
