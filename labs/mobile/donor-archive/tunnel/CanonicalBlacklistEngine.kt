package com.luminet.android.tunnel

import java.util.concurrent.ConcurrentHashMap

enum class BlacklistMatchVerdict {
    DIRECT,
    BLOCKED,
    WHITELISTED
}

class CanonicalBlacklistEngine {
    private val exactBlocked = ConcurrentHashMap<String, Boolean>()
    private val suffixBlocked = ConcurrentHashMap<String, Boolean>()
    private val exactWhitelist = ConcurrentHashMap<String, Boolean>()
    private val suffixWhitelist = ConcurrentHashMap<String, Boolean>()
    private val keywords = mutableListOf<String>()

    fun parseRawRule(line: String) {
        val trimmed = line.trim()
        if (trimmed.isEmpty() || trimmed.startsWith("!") || trimmed.startsWith("[")) return

        if (trimmed.startsWith("@@")) {
            val rule = trimmed.removePrefix("@@")
            if (rule.startsWith("||")) {
                suffixWhitelist[rule.removePrefix("||").trimStart('.').lowercase()] = true
            } else {
                val clean = rule.removePrefix("|").removePrefix("http://").removePrefix("https://").trimStart('.').lowercase()
                exactWhitelist[clean] = true
            }
            return
        }

        if (trimmed.startsWith("||")) {
            suffixBlocked[trimmed.removePrefix("||").trimStart('.').lowercase()] = true
            return
        }

        if (trimmed.startsWith("|")) {
            val clean = trimmed.removePrefix("|").removePrefix("http://").removePrefix("https://").trimStart('.').lowercase()
            exactBlocked[clean] = true
            return
        }

        if (!trimmed.startsWith("/")) {
            keywords.add(trimmed.lowercase())
        }
    }

    fun evaluateTarget(host: String): Pair<BlacklistMatchVerdict, String> {
        val hostLower = host.trim().trimEnd('.').lowercase()

        // 1. Whitelist
        if (exactWhitelist[hostLower] == true) return Pair(BlacklistMatchVerdict.WHITELISTED, hostLower)
        for (suf in suffixWhitelist.keys) {
            if (hostLower == suf || hostLower.endsWith(".$suf")) {
                return Pair(BlacklistMatchVerdict.WHITELISTED, suf)
            }
        }

        // 2. Exact blocked
        if (exactBlocked[hostLower] == true) return Pair(BlacklistMatchVerdict.BLOCKED, hostLower)

        // 3. Suffix blocked
        for (suf in suffixBlocked.keys) {
            if (hostLower == suf || hostLower.endsWith(".$suf")) {
                return Pair(BlacklistMatchVerdict.BLOCKED, suf)
            }
        }

        // 4. Keyword
        for (kw in keywords) {
            if (hostLower.contains(kw)) {
                return Pair(BlacklistMatchVerdict.BLOCKED, kw)
            }
        }

        return Pair(BlacklistMatchVerdict.DIRECT, "")
    }
}
