package com.luminet.android.tunnel

data class AndroidOrchestratorSummary(
    val totalCrawled: Int,
    val totalActivePool: Int,
    val usableTierACount: Int,
    val currentPacRulesCount: Int,
    val pacChecksum: String
)

class PacSubscriptionOrchestrator(initialDomains: List<String>, val defaultProxyPort: Int = 10808) {
    private val crawler = SubscriptionCrawlerPipeline()
    private val pool = NodePoolAggregator()
    private val classifier = SubscriptionHealthClassifier(10)
    private var pacGen = PacRuleGenerator(PacRuleAction.DIRECT)
    private val pacSync = PacDiffSynchronizer(initialDomains)

    init {
        for (d in initialDomains) {
            pacGen.addRule(d, PacRuleAction.PROXY, "127.0.0.1:$defaultProxyPort")
        }
    }

    fun registerSubscriptionSource(url: String, intervalSecs: Long) {
        crawler.addSource(url, intervalSecs)
    }

    fun executeCrawlAndIngest(sourceUrl: String, rawContent: String, now: Long): Int {
        val count = crawler.ingestCrawlContent(sourceUrl, rawContent)
        val proxies = crawler.getHarvestedProxies()
        pool.ingestRawEntries(proxies, now)
        return count
    }

    fun recordNodeProbe(nodeId: String, latencyMs: Int, success: Boolean) {
        classifier.recordSample(nodeId, latencyMs, success)
        pool.updateHealth(nodeId, latencyMs, success)
    }

    fun updatePacWithUpstream(upstreamDomains: List<String>): PacSyncDelta {
        val delta = pacSync.computeDelta(upstreamDomains)
        pacSync.applyDelta(delta)

        pacGen = PacRuleGenerator(PacRuleAction.DIRECT)
        for (d in upstreamDomains) {
            pacGen.addRule(d, PacRuleAction.PROXY, "127.0.0.1:$defaultProxyPort")
        }

        return delta
    }

    fun exportActivePacScript(): String {
        return pacGen.generatePacScript()
    }

    fun getSummary(): AndroidOrchestratorSummary {
        val tierA = classifier.filterUsableNodes(HealthTier.TIER_A_EXCELLENT)
        return AndroidOrchestratorSummary(
            totalCrawled = crawler.totalHarvestedCount(),
            totalActivePool = pool.rankNodes(0.0).size,
            usableTierACount = tierA.size,
            currentPacRulesCount = pacSync.totalRules(),
            pacChecksum = pacSync.currentChecksum()
        )
    }
}
