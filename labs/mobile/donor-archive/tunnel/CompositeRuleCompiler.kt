package com.luminet.android.tunnel

enum class AndroidRuleAction {
    DIRECT, PROXY, REJECT
}

sealed class AndroidRuleCriterion {
    data class Domain(val pattern: String) : AndroidRuleCriterion()
    data class DomainSuffix(val pattern: String) : AndroidRuleCriterion()
    data class DomainKeyword(val pattern: String) : AndroidRuleCriterion()
    data class IpCidr(val netAddr: Long, val mask: Long) : AndroidRuleCriterion()
    data class UserAgent(val pattern: String) : AndroidRuleCriterion()
}

data class AndroidCompiledRule(
    val criterion: AndroidRuleCriterion,
    val action: AndroidRuleAction
)

class CompositeRuleCompiler {
    private val rules = mutableListOf<AndroidCompiledRule>()

    fun parseLine(line: String): Boolean {
        val trimmed = line.trim()
        if (trimmed.isEmpty() || trimmed.startsWith("#") || trimmed.startsWith("//")) {
            return false
        }
        val parts = trimmed.split(",").map { it.trim() }
        if (parts.size < 3) return false

        val rType = parts[0].uppercase()
        val pattern = parts[1]
        val action = when (parts[2].uppercase()) {
            "DIRECT" -> AndroidRuleAction.DIRECT
            "PROXY" -> AndroidRuleAction.PROXY
            "REJECT" -> AndroidRuleAction.REJECT
            else -> return false
        }

        val criterion = when (rType) {
            "DOMAIN" -> AndroidRuleCriterion.Domain(pattern.lowercase())
            "DOMAIN-SUFFIX" -> AndroidRuleCriterion.DomainSuffix(pattern.lowercase())
            "DOMAIN-KEYWORD" -> AndroidRuleCriterion.DomainKeyword(pattern.lowercase())
            "IP-CIDR" -> {
                val cidrParts = pattern.split("/")
                val ipStr = cidrParts[0]
                val maskBits = if (cidrParts.size > 1) cidrParts[1].toIntOrNull() ?: 32 else 32
                val ipLong = parseIpv4ToLong(ipStr) ?: return false
                val mask = if (maskBits == 0) 0L else (0xFFFFFFFFL shl (32 - maskBits)) and 0xFFFFFFFFL
                AndroidRuleCriterion.IpCidr(ipLong and mask, mask)
            }
            "USER-AGENT" -> AndroidRuleCriterion.UserAgent(pattern)
            else -> return false
        }

        rules.add(AndroidCompiledRule(criterion, action))
        return true
    }

    fun evaluateDomain(domain: String): AndroidRuleAction? {
        val clean = domain.trim().lowercase()
        for (r in rules) {
            when (val crit = r.criterion) {
                is AndroidRuleCriterion.Domain -> {
                    if (clean == crit.pattern) return r.action
                }
                is AndroidRuleCriterion.DomainSuffix -> {
                    if (clean == crit.pattern || clean.endsWith(".${crit.pattern}")) return r.action
                }
                is AndroidRuleCriterion.DomainKeyword -> {
                    if (clean.contains(crit.pattern)) return r.action
                }
                else -> {}
            }
        }
        return null
    }

    fun evaluateIp(ipStr: String): AndroidRuleAction? {
        val ipLong = parseIpv4ToLong(ipStr) ?: return null
        for (r in rules) {
            if (r.criterion is AndroidRuleCriterion.IpCidr) {
                val crit = r.criterion
                if ((ipLong and crit.mask) == crit.netAddr) {
                    return r.action
                }
            }
        }
        return null
    }

    fun ruleCount(): Int = rules.size

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
