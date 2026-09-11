package com.luminet.android.tunnel

import java.util.concurrent.ConcurrentHashMap

data class AndroidSniRewriteRule(
    val originalDomain: String,
    val alteredSni: String,
    val validSans: List<String>,
    val skipCertVerify: Boolean = false
)

class SniHostnameRewriter {
    private val rules = ConcurrentHashMap<String, AndroidSniRewriteRule>()
    private val httpRedirects = ConcurrentHashMap<String, String>()
    var totalRewrites: Long = 0L
        private set

    fun addSniRule(original: String, altered: String, sans: List<String>, skipVerify: Boolean = false) {
        val key = original.trim().trimEnd('.').lowercase()
        rules[key] = AndroidSniRewriteRule(
            originalDomain = key,
            alteredSni = altered.trim().trimEnd('.').lowercase(),
            validSans = sans.map { it.lowercase() },
            skipCertVerify = skipVerify
        )
    }

    fun addHttpRedirect(prefix: String, targetUrl: String) {
        httpRedirects[prefix] = targetUrl
    }

    fun resolveSni(domain: String): Pair<String, AndroidSniRewriteRule?> {
        val key = domain.trim().trimEnd('.').lowercase()
        rules[key]?.let {
            totalRewrites++
            return Pair(it.alteredSni, it)
        }
        return Pair(domain, null)
    }

    fun checkSanValidity(rule: AndroidSniRewriteRule, presentedSans: List<String>): Boolean {
        if (rule.skipCertVerify) return true
        for (valid in rule.validSans) {
            for (pres in presentedSans) {
                val pLower = pres.lowercase()
                if (valid.startsWith("*.")) {
                    val suffix = valid.removePrefix("*.")
                    if (pLower.endsWith(suffix)) return true
                } else if (pLower == valid) {
                    return true
                }
            }
        }
        return false
    }

    fun checkHttpRedirect(url: String): String? {
        for ((prefix, target) in httpRedirects) {
            if (url.startsWith(prefix)) {
                return "https://$target"
            }
        }
        return null
    }
}
