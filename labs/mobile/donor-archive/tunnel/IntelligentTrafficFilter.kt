package com.luminet.android.tunnel

sealed class AndroidFilterVerdict {
    data class BlockedDns(val category: BlockCategory) : AndroidFilterVerdict()
    data class ProxyRequired(val ruleHit: String, val egressTag: String) : AndroidFilterVerdict()
    data class DirectPassThrough(val egressTag: String) : AndroidFilterVerdict()
}

class IntelligentTrafficFilter(
    val defaultEgress: String
) {
    val dnsBlocklist = DnsBlocklistEngine()
    val canonicalBlacklist = CanonicalBlacklistEngine()
    val geoRouter = GeospatialPolygonRouter(defaultEgress)
    val flowAnalyzer = FlowAnalyzerEngine()
    var totalEvaluated: Long = 0L
        private set

    fun evaluateTraffic(
        src: String,
        dst: String,
        domain: String?,
        userLocation: AndroidGeoPoint?,
        initialPayload: ByteArray
    ): AndroidFilterVerdict {
        totalEvaluated++

        // 1. Flow telemetry
        flowAnalyzer.registerFlow(src, dst, initialPayload)

        // 2. DNS Blocklist Check
        if (!domain.isNullOrEmpty()) {
            dnsBlocklist.isDomainBlocked(domain)?.let {
                return AndroidFilterVerdict.BlockedDns(it)
            }
        }

        // 3. Resolve spatial egress
        val spatialEgress = if (userLocation != null) {
            geoRouter.resolveEgress(userLocation).first
        } else {
            defaultEgress
        }

        // 4. Blacklist matching
        if (!domain.isNullOrEmpty()) {
            val (verdict, rule) = canonicalBlacklist.evaluateTarget(domain)
            if (verdict == BlacklistMatchVerdict.BLOCKED) {
                return AndroidFilterVerdict.ProxyRequired(rule, "tunnel-proxy")
            }
        }

        return AndroidFilterVerdict.DirectPassThrough(spatialEgress)
    }
}
