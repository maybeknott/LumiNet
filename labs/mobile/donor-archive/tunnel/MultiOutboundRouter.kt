package com.luminet.android.tunnel

sealed class AndroidOutboundPolicy {
    object Direct : AndroidOutboundPolicy()
    data class Proxy(val tag: String) : AndroidOutboundPolicy()
    object Reject : AndroidOutboundPolicy()
}

data class AndroidOutboundRule(
    val pattern: String,
    val isSuffix: Boolean,
    val policy: AndroidOutboundPolicy
)

class MultiOutboundRouter(private val defaultPolicy: AndroidOutboundPolicy = AndroidOutboundPolicy.Direct) {
    private val rules = mutableListOf<AndroidOutboundRule>()
    private val outboundWeights = mutableMapOf<String, Int>()
    private var rrCounter = 0

    fun addRule(pattern: String, isSuffix: Boolean, policy: AndroidOutboundPolicy) {
        rules.add(
            AndroidOutboundRule(
                pattern = pattern.trim().lowercase(),
                isSuffix = isSuffix,
                policy = policy
            )
        )
    }

    fun registerOutbound(tag: String, weight: Int) {
        outboundWeights[tag] = if (weight < 1) 1 else weight
    }

    fun matchTarget(host: String): AndroidOutboundPolicy {
        val clean = host.trim().lowercase()
        for (r in rules) {
            if (r.isSuffix) {
                if (clean == r.pattern || clean.endsWith(".${r.pattern}")) {
                    return r.policy
                }
            } else if (clean == r.pattern) {
                return r.policy
            }
        }
        return defaultPolicy
    }

    fun selectBalancedOutbound(outbounds: List<String>): String? {
        if (outbounds.isEmpty()) return null
        val chosen = outbounds[rrCounter % outbounds.size]
        rrCounter++
        return chosen
    }
}
