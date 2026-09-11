package com.luminet.android.tunnel

enum class AndroidPolicyVerdict {
    DIRECT, PROXY, REJECT
}

data class AndroidCidrRule(
    val netAddr: Long,
    val mask: Long,
    val verdict: AndroidPolicyVerdict
)

class PolicyRulesetRouter(private val defaultPolicy: AndroidPolicyVerdict = AndroidPolicyVerdict.DIRECT) {
    private val exactDomains = mutableMapOf<String, AndroidPolicyVerdict>()
    private val suffixDomains = mutableMapOf<String, AndroidPolicyVerdict>()
    private val keywordRules = mutableListOf<Pair<String, AndroidPolicyVerdict>>()
    private val cidrRules = mutableListOf<AndroidCidrRule>()
    private val cache = mutableMapOf<String, AndroidPolicyVerdict>()

    fun addExactDomain(domain: String, verdict: AndroidPolicyVerdict) {
        exactDomains[domain.trim().lowercase()] = verdict
    }

    fun addSuffixDomain(suffix: String, verdict: AndroidPolicyVerdict) {
        val clean = suffix.trim().lowercase().removePrefix(".")
        suffixDomains[clean] = verdict
    }

    fun addKeyword(keyword: String, verdict: AndroidPolicyVerdict) {
        keywordRules.add(keyword.trim().lowercase() to verdict)
    }

    fun addCidr(ipStr: String, maskBits: Int, verdict: AndroidPolicyVerdict) {
        val ipLong = parseIpv4ToLong(ipStr) ?: return
        val mask = if (maskBits == 0) 0L else (0xFFFFFFFFL shl (32 - maskBits)) and 0xFFFFFFFFL
        cidrRules.add(AndroidCidrRule(ipLong and mask, mask, verdict))
    }

    fun resolveDomain(domain: String): AndroidPolicyVerdict {
        val clean = domain.trim().lowercase()
        cache[clean]?.let { return it }

        // 1. Exact match
        exactDomains[clean]?.let {
            cache[clean] = it
            return it
        }

        // 2. Suffix match
        for ((suffix, v) in suffixDomains) {
            if (clean == suffix || clean.endsWith(".$suffix")) {
                cache[clean] = v
                return v
            }
        }

        // 3. Keyword match
        for ((kw, v) in keywordRules) {
            if (clean.contains(kw)) {
                cache[clean] = v
                return v
            }
        }

        cache[clean] = defaultPolicy
        return defaultPolicy
    }

    fun resolveIp(ipStr: String): AndroidPolicyVerdict {
        val ipLong = parseIpv4ToLong(ipStr) ?: return defaultPolicy
        for (c in cidrRules) {
            if ((ipLong and c.mask) == c.netAddr) {
                return c.verdict
            }
        }
        return defaultPolicy
    }

    fun clearCache() {
        cache.clear()
    }

    private fun parseIpv4ToLong(ip: String): Long? {
        val parts = ip.split(".")
        if (parts.size != 4) return null
        var res = 0L
        for (p in parts) {
            val octet = p.toLongOrNull() ?: return null
            if (octet !in 0..255) return null
            res = (res shl 8) or octet
        }
        return res
    }
}
