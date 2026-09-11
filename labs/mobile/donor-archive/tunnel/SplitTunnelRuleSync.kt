package com.luminet.android.tunnel

import java.net.InetAddress
import java.util.concurrent.CopyOnWriteArrayList

enum class AndroidSplitAction {
    ROUTE_THROUGH_VPN,
    BYPASS_VPN,
    DROP_TRAFFIC
}

data class AndroidSplitRule(
    val id: String,
    val networkStr: String,
    val prefixLen: Int,
    val action: AndroidSplitAction,
    val priority: Int
)

class SplitTunnelRuleSync(val defaultAction: AndroidSplitAction = AndroidSplitAction.BYPASS_VPN) {
    val rules = CopyOnWriteArrayList<AndroidSplitRule>()
    var syncVersion: Long = 0
        private set

    fun addRule(id: String, cidr: String, action: AndroidSplitAction, priority: Int) {
        val parts = cidr.trim().split("/")
        val netStr = parts[0]
        val prefix = if (parts.size == 2) parts[1].toInt() else 32

        val rule = AndroidSplitRule(id, netStr, prefix, action, priority)
        rules.add(rule)
        rules.sortWith(compareByDescending<AndroidSplitRule> { it.priority }.thenByDescending { it.prefixLen })
        syncVersion++
    }

    fun matchIp(destIp: String): AndroidSplitAction {
        for (rule in rules) {
            if (matchesCidr(destIp, rule.networkStr, rule.prefixLen)) {
                return rule.action
            }
        }
        return defaultAction
    }

    fun syncFromFeed(feedContent: String, action: AndroidSplitAction): Int {
        var count = 0
        for (line in feedContent.lines()) {
            val trimmed = line.trim()
            if (trimmed.isEmpty() || trimmed.startsWith("#")) continue
            addRule("feed-${count + 1}", trimmed, action, 100)
            count++
        }
        return count
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
