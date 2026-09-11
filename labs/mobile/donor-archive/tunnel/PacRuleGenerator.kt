package com.luminet.android.tunnel

enum class PacRuleAction {
    DIRECT,
    PROXY
}

data class PacRuleEntry(
    val pattern: String,
    val isExact: Boolean,
    val isSuffix: Boolean,
    val action: PacRuleAction,
    val proxyEndpoint: String
)

class PacRuleGenerator(
    private val defaultAction: PacRuleAction = PacRuleAction.DIRECT,
    private val defaultProxy: String = ""
) {
    private val rules = ArrayList<PacRuleEntry>()

    fun addRule(pattern: String, action: PacRuleAction, proxyEndpoint: String) {
        val trimmed = pattern.trim().lowercase()
        var isExact = false
        var isSuffix = false
        var pat = trimmed

        if (trimmed.startsWith("||")) {
            isSuffix = true
            pat = trimmed.substring(2)
        } else if (trimmed.startsWith("|")) {
            isExact = true
            pat = trimmed.substring(1)
        }

        rules.add(PacRuleEntry(pat, isExact, isSuffix, action, proxyEndpoint))
    }

    fun evaluateHost(host: String): Pair<PacRuleAction, String> {
        val hostLower = host.lowercase()
        for (r in rules) {
            if (r.isExact) {
                if (hostLower == r.pattern) return Pair(r.action, r.proxyEndpoint)
            } else if (r.isSuffix) {
                if (hostLower == r.pattern || hostLower.endsWith(".${r.pattern}")) {
                    return Pair(r.action, r.proxyEndpoint)
                }
            } else if (hostLower.contains(r.pattern)) {
                return Pair(r.action, r.proxyEndpoint)
            }
        }
        return Pair(defaultAction, defaultProxy)
    }

    fun generatePacScript(): String {
        val rulesJs = rules.filter { it.action == PacRuleAction.PROXY }.map {
            "  \"${it.pattern}\": \"PROXY ${it.proxyEndpoint}\","
        }
        val defRet = if (defaultAction == PacRuleAction.PROXY) "\"PROXY $defaultProxy\"" else "\"DIRECT\""

        return """
// LumiNet Generated PAC
var rules = {
${rulesJs.joinToString("\n")}
};

function FindProxyForURL(url, host) {
    for (var d in rules) {
        if (dnsDomainIs(host, d) || host === d) {
            return rules[d];
        }
    }
    return $defRet;
}
""".trimIndent()
    }
}
