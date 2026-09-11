package com.luminet.android.tunnel

import java.net.InetAddress
import java.util.concurrent.CopyOnWriteArrayList

enum class AndroidRuleKind {
    DOMAIN,
    DOMAIN_SUFFIX,
    DOMAIN_KEYWORD,
    IP_CIDR,
    PORT_RANGE,
    PROCESS_NAME,
    MATCH
}

data class AndroidRoutingRule(
    val kind: AndroidRuleKind,
    val value: String = "",
    val cidrNet: String = "",
    val cidrPrefix: Int = 32,
    val portStart: Int = 0,
    val portEnd: Int = 0,
    val targetOutbound: String,
    val priority: Int
)

data class AndroidTrafficTarget(
    val domain: String? = null,
    val ip: String? = null,
    val port: Int = 0,
    val processName: String? = null
)

class AsyncRuleEvaluator(val defaultOutbound: String = "DIRECT") {
    val rules = CopyOnWriteArrayList<AndroidRoutingRule>()

    fun addRule(rule: AndroidRoutingRule) {
        rules.add(rule)
        rules.sortByDescending { it.priority }
    }

    fun evaluate(target: AndroidTrafficTarget): String {
        for (rule in rules) {
            if (matches(rule, target)) {
                return rule.targetOutbound
            }
        }
        return defaultOutbound
    }

    private fun matches(rule: AndroidRoutingRule, target: AndroidTrafficTarget): Boolean {
        return when (rule.kind) {
            AndroidRuleKind.DOMAIN -> {
                target.domain?.equals(rule.value, ignoreCase = true) ?: false
            }
            AndroidRuleKind.DOMAIN_SUFFIX -> {
                val d = target.domain?.lowercase() ?: return false
                val s = rule.value.lowercase()
                d == s || d.endsWith(".$s")
            }
            AndroidRuleKind.DOMAIN_KEYWORD -> {
                target.domain?.lowercase()?.contains(rule.value.lowercase()) ?: false
            }
            AndroidRuleKind.IP_CIDR -> {
                if (target.ip == null || rule.cidrNet.isEmpty()) false
                else matchesCidr(target.ip, rule.cidrNet, rule.cidrPrefix)
            }
            AndroidRuleKind.PORT_RANGE -> {
                target.port in rule.portStart..rule.portEnd
            }
            AndroidRuleKind.PROCESS_NAME -> {
                target.processName?.equals(rule.value, ignoreCase = true) ?: false
            }
            AndroidRuleKind.MATCH -> true
        }
    }

    private fun matchesCidr(ipStr: String, netStr: String, prefix: Int): Boolean {
        return try {
            val netAddr = InetAddress.getByName(netStr).address
            val targetAddr = InetAddress.getByName(ipStr).address
            if (prefix == 0) return true

            var matched = true
            var bits = prefix
            for (i in netAddr.indices) {
                if (bits >= 8) {
                    if (netAddr[i] != targetAddr[i]) { matched = false; break }
                    bits -= 8
                } else if (bits > 0) {
                    val mask = (0xFF shl (8 - bits)) and 0xFF
                    if ((netAddr[i].toInt() and mask) != (targetAddr[i].toInt() and mask)) { matched = false; break }
                    bits = 0
                } else break
            }
            matched
        } catch (e: Exception) {
            false
        }
    }
}
