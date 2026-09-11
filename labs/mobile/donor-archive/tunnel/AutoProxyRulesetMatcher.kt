package com.luminet.android.tunnel

class AutoProxyRulesetMatcher {
    private val directRules = mutableListOf<String>()
    private val proxyRules = mutableListOf<String>()

    fun parseLine(line: String) {
        val trimmed = line.trim()
        if (trimmed.isEmpty() || trimmed.startsWith("!") || trimmed.startsWith("[")) return

        if (trimmed.startsWith("@@")) {
            val rule = trimmed.removePrefix("@@").removePrefix("||").removePrefix("|").lowercase()
            directRules.add(rule)
        } else {
            val rule = trimmed.removePrefix("||").removePrefix("|").lowercase()
            proxyRules.add(rule)
        }
    }

    fun match(url: String): String? {
        val lower = url.lowercase()
        for (r in directRules) {
            if (lower.contains(r)) return "DIRECT"
        }
        for (r in proxyRules) {
            if (lower.contains(r)) return "PROXY"
        }
        return null
    }
}
