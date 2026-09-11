package com.luminet.android.tunnel

import java.util.concurrent.ConcurrentHashMap

enum class BlockCategory {
    MALWARE,
    ADVERTISING,
    TRACKING,
    CRYPTOMINING,
    ADULT,
    TELEMETRY
}

class DnsBlocklistEngine {
    private val exactRules = ConcurrentHashMap<String, BlockCategory>()
    private val wildcardRules = ConcurrentHashMap<String, BlockCategory>()
    private val whitelist = ConcurrentHashMap<String, Boolean>()
    private val blockedIps = ConcurrentHashMap<String, Boolean>()

    fun addExactRule(domain: String, category: BlockCategory) {
        val clean = domain.trim().trimEnd('.').lowercase()
        if (clean.isNotEmpty()) {
            exactRules[clean] = category
        }
    }

    fun addWildcardRule(suffix: String, category: BlockCategory) {
        var clean = suffix.trim().trimEnd('.').lowercase()
        if (clean.startsWith("*.")) clean = clean.substring(2)
        if (clean.startsWith(".")) clean = clean.substring(1)
        if (clean.isNotEmpty()) {
            wildcardRules[clean] = category
        }
    }

    fun addWhitelist(domain: String) {
        val clean = domain.trim().trimEnd('.').lowercase()
        if (clean.isNotEmpty()) {
            whitelist[clean] = true
        }
    }

    fun addBlockedIp(ip: String) {
        blockedIps[ip.trim()] = true
    }

    fun isDomainBlocked(domain: String): BlockCategory? {
        val clean = domain.trim().trimEnd('.').lowercase()

        // 1. Whitelist check
        if (whitelist[clean] == true) return null
        val parts = clean.split(".")
        for (i in 1 until parts.size) {
            val parent = parts.subList(i, parts.size).joinToString(".")
            if (whitelist[parent] == true) return null
        }

        // 2. Exact match check
        exactRules[clean]?.let { return it }

        // 3. Wildcard suffix check
        for ((suffix, cat) in wildcardRules) {
            if (clean == suffix || clean.endsWith(".$suffix")) {
                return cat
            }
        }
        return null
    }

    fun isIpBlocked(ip: String): Boolean = blockedIps[ip.trim()] == true
}
