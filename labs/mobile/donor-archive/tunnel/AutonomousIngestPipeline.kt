package com.luminet.android.tunnel

class AutonomousIngestPipeline(defaultPolicy: AndroidPolicyVerdict = AndroidPolicyVerdict.DIRECT) {
    val deduplicator = NodeIngestDeduplicator()
    val geoip = EnhancedGeoIpLookup()
    val ruleCompiler = CompositeRuleCompiler()
    val policyRouter = PolicyRulesetRouter(defaultPolicy)
    var totalIngested: Int = 0
        private set

    fun ingestSubscriptionManifest(sourceName: String, b64Manifest: String): Int {
        val extractor = SubscriptionNodeExtractor()
        val nodes = extractor.decodeSubscription(b64Manifest)
        var added = 0

        for (node in nodes) {
            val scraped = AndroidScrapedNode(
                host = node.address,
                port = node.port,
                protocol = node.nodeType.name.lowercase(),
                source = sourceName,
                pingMs = 100L,
                isAlive = true
            )
            if (deduplicator.ingestNode(scraped)) {
                added++
            }
        }
        totalIngested += added
        return added
    }

    fun evaluateEgress(targetDomain: String, destIpStr: String? = null): AndroidPolicyVerdict {
        // 1. Composite rule check
        ruleCompiler.evaluateDomain(targetDomain)?.let { act ->
            return when (act) {
                AndroidRuleAction.DIRECT -> AndroidPolicyVerdict.DIRECT
                AndroidRuleAction.PROXY -> AndroidPolicyVerdict.PROXY
                AndroidRuleAction.REJECT -> AndroidPolicyVerdict.REJECT
            }
        }

        // 2. IP GeoIP check
        if (destIpStr != null) {
            ruleCompiler.evaluateIp(destIpStr)?.let { act ->
                return when (act) {
                    AndroidRuleAction.DIRECT -> AndroidPolicyVerdict.DIRECT
                    AndroidRuleAction.PROXY -> AndroidPolicyVerdict.PROXY
                    AndroidRuleAction.REJECT -> AndroidPolicyVerdict.REJECT
                }
            }
            if (geoip.lookup(destIpStr) == "CN") {
                return AndroidPolicyVerdict.DIRECT
            }
        }

        // 3. Fallback to policy router
        return policyRouter.resolveDomain(targetDomain)
    }
}
