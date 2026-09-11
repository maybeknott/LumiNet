package com.luminet.android.tunnel

data class ParsedSubscriptionNode(
    val protocol: String,
    val endpoint: String,
    val tag: String
)

class SubscriptionPipeline {
    fun parse(content: String): List<ParsedSubscriptionNode> {
        val lines = content.trim().split("\n")
        val nodes = mutableListOf<ParsedSubscriptionNode>()
        val seen = mutableSetOf<String>()

        for (line in lines) {
            val trimmed = line.trim()
            if (trimmed.isBlank() || trimmed.startsWith("#")) continue
            if (!trimmed.contains("://")) continue

            val parts = trimmed.split("://", limit = 2)
            val protocol = parts[0]
            var rest = parts[1]
            var tag = ""

            if (rest.contains("#")) {
                val tagParts = rest.split("#", limit = 2)
                rest = tagParts[0]
                tag = tagParts[1]
            }

            if (seen.add(trimmed)) {
                nodes.add(ParsedSubscriptionNode(protocol, rest, tag))
            }
        }
        return nodes
    }
}
