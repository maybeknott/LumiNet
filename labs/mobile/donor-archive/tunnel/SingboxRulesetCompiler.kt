package com.luminet.android.tunnel

data class AndroidSingboxRule(
    val type: String,
    val value: String,
    val outbound: String
)

class SingboxRulesetCompiler {
    val rules = mutableListOf<AndroidSingboxRule>()

    fun addRule(type: String, value: String, outbound: String) {
        rules.add(AndroidSingboxRule(type, value, outbound))
    }

    fun matchDomain(domain: String): String? {
        val lower = domain.trim().trimStart('.').lowercase()
        for (r in rules) {
            if (r.type == "domain_suffix") {
                if (lower == r.value || lower.endsWith(".${r.value}")) return r.outbound
            } else if (r.type == "domain") {
                if (lower == r.value) return r.outbound
            } else if (r.type == "geosite" && r.value == "cn") {
                if (lower.endsWith(".cn") || lower.contains("baidu")) return r.outbound
            }
        }
        return null
    }

    fun exportJson(): String {
        val sb = StringBuilder()
        sb.append("{\n  \"version\": 1,\n  \"rules\": [\n")
        for ((idx, r) in rules.withIndex()) {
            val comma = if (idx + 1 < rules.size) "," else ""
            sb.append("    {\"").append(r.type).append("\": [\"").append(r.value).append("\"], \"outbound\": \"").append(r.outbound).append("\"}").append(comma).append("\n")
        }
        sb.append("  ]\n}\n")
        return sb.toString()
    }
}
