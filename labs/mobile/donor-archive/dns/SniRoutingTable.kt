package com.luminet.android.dns

import java.util.concurrent.locks.ReentrantReadWriteLock
import kotlin.concurrent.read
import kotlin.concurrent.write

/**
 * SNI Domain Routing Table & Destination IP Rewriter.
 * Ported and unified from `smartSNI-main`.
 * Conforms to strict architectural isolation rules: zero vendor prefixes.
 */
class SniRoutingTable {
    private val lock = ReentrantReadWriteLock()
    private val exact = HashMap<String, String>()
    private val wildcards = HashMap<String, String>()
    private val contains = HashMap<String, String>()

    fun addExactRoute(domain: String, targetIp: String) {
        val clean = cleanDomain(domain)
        lock.write {
            exact[clean] = targetIp
        }
    }

    fun addWildcardRoute(suffix: String, targetIp: String) {
        val clean = cleanSuffix(suffix)
        lock.write {
            wildcards[clean] = targetIp
        }
    }

    fun addSubstringRoute(substr: String, targetIp: String) {
        val clean = substr.trim().lowercase()
        lock.write {
            contains[clean] = targetIp
        }
    }

    fun resolveRoute(domain: String): String? {
        val clean = cleanDomain(domain)
        lock.read {
            // 1. Exact match
            exact[clean]?.let { return it }

            // 2. Wildcard suffix match
            for ((suffix, ip) in wildcards) {
                if (clean == suffix || clean.endsWith(".$suffix")) {
                    return ip
                }
            }

            // 3. Substring match
            for ((substr, ip) in contains) {
                if (clean.contains(substr)) {
                    return ip
                }
            }
        }
        return null
    }

    fun totalRoutes(): Int {
        lock.read {
            return exact.size + wildcards.size + contains.size
        }
    }

    private fun cleanDomain(domain: String): String {
        return domain.trim().trimEnd('.').lowercase()
    }

    private fun cleanSuffix(suffix: String): String {
        var clean = suffix.trim().lowercase()
        while (clean.startsWith("*") || clean.startsWith(".")) {
            clean = clean.substring(1)
        }
        return clean.trimEnd('.')
    }
}
