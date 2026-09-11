// Copyright 2024-2026 LumiNet Authors. All Rights Reserved.
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

package com.luminet.android.tunnel

/**
 * Routing rule category for PAC decisions.
 */
enum class PacRuleType(val wireName: String) {
    DOMAIN("domain"),
    IP("ip"),
    RANGE("range"),
    APP("app");

    companion object {
        fun fromWire(value: String): PacRuleType {
            val normalized = value.trim().lowercase()
            return entries.find { it.wireName == normalized } ?: DOMAIN
        }
    }
}

/**
 * Parsed routing directive.
 */
data class PacRule(
    val ruleType: PacRuleType,
    val value: String,
    val isWildcard: Boolean,
    val forceProxy: Boolean
)

/**
 * Proxy routing decision.
 */
enum class PacDecision {
    DIRECT,
    PROXY,
    DEFAULT_PROXY
}

/**
 * Pure Kotlin implementation of the PAC script compiler and offline rule evaluator.
 */
object PacRoutingEngine {

    fun parseRules(rulesStr: String): List<PacRule> {
        val rules = mutableListOf<PacRule>()
        if (rulesStr.trim().isEmpty()) return rules

        val cleaned = rulesStr
            .replace("<br>", ",")
            .replace("\n", ",")
            .replace("\r", "")

        val tokens = cleaned.split(",")
        for (token in tokens) {
            val t = token.trim()
            if (t.isEmpty() || t.startsWith("app:")) continue

            var typeStr = "domain"
            var rawVal = t

            val colonIdx = t.indexOf(':')
            if (colonIdx != -1) {
                typeStr = t.substring(0, colonIdx).trim().lowercase()
                rawVal = t.substring(colonIdx + 1).trim()
            }

            var forceProxy = false
            if (typeStr.startsWith("!")) {
                forceProxy = true
                typeStr = typeStr.substring(1)
            }
            if (rawVal.startsWith("!")) {
                forceProxy = true
                rawVal = rawVal.substring(1)
            }

            val isWildcard = typeStr.startsWith("*") || rawVal.startsWith("*") || rawVal.contains("*")
            typeStr = typeStr.removePrefix("*")
            val cleanVal = rawVal.removePrefix("*")

            rules.add(
                PacRule(
                    ruleType = PacRuleType.fromWire(typeStr),
                    value = cleanVal,
                    isWildcard = isWildcard,
                    forceProxy = forceProxy
                )
            )
        }

        return rules
    }

    fun evaluateHost(host: String, rules: List<PacRule>): PacDecision {
        val hostLower = host.trim().lowercase()
        if (hostLower == "127.0.0.1" || hostLower == "::1" || hostLower == "localhost") {
            return PacDecision.DIRECT
        }

        for (rule in rules) {
            val ruleValLower = rule.value.lowercase()

            when (rule.ruleType) {
                PacRuleType.DOMAIN -> {
                    if (rule.isWildcard) {
                        if (hostLower.endsWith(ruleValLower) || hostLower == ruleValLower) {
                            return if (rule.forceProxy) PacDecision.PROXY else PacDecision.DIRECT
                        }
                    } else if (hostLower == ruleValLower) {
                        return if (rule.forceProxy) PacDecision.PROXY else PacDecision.DIRECT
                    }
                }
                PacRuleType.IP, PacRuleType.RANGE -> {
                    if (rule.isWildcard) {
                        val prefix = ruleValLower.trimEnd('*')
                        if (hostLower.startsWith(prefix)) {
                            return if (rule.forceProxy) PacDecision.PROXY else PacDecision.DIRECT
                        }
                    } else if (hostLower == ruleValLower) {
                        return if (rule.forceProxy) PacDecision.PROXY else PacDecision.DIRECT
                    }
                }
                PacRuleType.APP -> {}
            }
        }

        return PacDecision.DEFAULT_PROXY
    }

    fun compilePacScript(
        proxyHost: String,
        proxyPort: Int,
        isSocks5: Boolean,
        rules: List<PacRule>
    ): String {
        val proxyDirective = if (isSocks5) {
            "SOCKS5 $proxyHost:$proxyPort; SOCKS $proxyHost:$proxyPort; DIRECT"
        } else {
            "PROXY $proxyHost:$proxyPort; DIRECT"
        }

        val sb = StringBuilder()
        for (rule in rules) {
            val valStr = rule.value
            if (rule.forceProxy && rule.ruleType == PacRuleType.DOMAIN) {
                if (rule.isWildcard) {
                    sb.append("  if (shExpMatch(host, \"*$valStr\")) return \"$proxyDirective\";\n")
                } else {
                    sb.append("  if (host === \"$valStr\") return \"$proxyDirective\";\n")
                }
            } else if (rule.ruleType == PacRuleType.DOMAIN) {
                if (rule.isWildcard) {
                    sb.append("  if (shExpMatch(host, \"*$valStr\")) return \"DIRECT\";\n")
                } else {
                    sb.append("  if (host === \"$valStr\") return \"DIRECT\";\n")
                }
            } else if (rule.ruleType == PacRuleType.IP || rule.ruleType == PacRuleType.RANGE) {
                if (rule.isWildcard) {
                    val prefix = valStr.trimEnd('*')
                    sb.append("  if (host.indexOf(\"$prefix\") === 0) return \"DIRECT\";\n")
                } else {
                    sb.append("  if (host === \"$valStr\") return \"DIRECT\";\n")
                }
            }
        }

        return """
            function FindProxyForURL(url, host) {
              "use strict";
              if (isPlainHostName(host) || /^127\./.test(host) || /^10\./.test(host) || /^172\.(1[6-9]|2[0-9]|3[01])\./.test(host) || /^192\.168\./.test(host) || host === "localhost" || host === "::1") {
                return "DIRECT";
              }
            $sb  return "$proxyDirective";
            }
        """.trimIndent()
    }
}

/**
 * Maps Cloudflare edge airport codes to country name and flag.
 */
object ColoLocationResolver {
    data class Location(val airportCode: String, val countryCode: String, val countryName: String, val flagEmoji: String)

    private val map = mapOf(
        "FRA" to Location("FRA", "DE", "Germany", "🇩🇪"),
        "LHR" to Location("LHR", "GB", "United Kingdom", "🇬🇧"),
        "AMS" to Location("AMS", "NL", "Netherlands", "🇳🇱"),
        "CDG" to Location("CDG", "FR", "France", "🇫🇷"),
        "DOH" to Location("DOH", "QA", "Qatar", "🇶🇦"),
        "DXB" to Location("DXB", "AE", "United Arab Emirates", "🇦🇪"),
        "IST" to Location("IST", "TR", "Turkey", "🇹🇷"),
        "NRT" to Location("NRT", "JP", "Japan", "🇯🇵"),
        "SIN" to Location("SIN", "SG", "Singapore", "🇸🇬"),
        "HKG" to Location("HKG", "HK", "Hong Kong", "🇭🇰"),
        "LAX" to Location("LAX", "US", "United States", "🇺🇸"),
        "JFK" to Location("JFK", "US", "United States", "🇺🇸"),
        "ORD" to Location("ORD", "US", "United States", "🇺🇸")
    )

    fun resolve(airportCode: String): Location {
        val code = airportCode.trim().uppercase()
        return map[code] ?: Location(code, "XX", "Global Edge", "🌐")
    }
}
