package com.luminet.android.tunnel

enum class HealthTier {
    TIER_F_DEAD,
    TIER_C_DEGRADED,
    TIER_B_GOOD,
    TIER_A_EXCELLENT
}

data class NodeProbeStats(
    val samples: ArrayList<Int> = ArrayList(),
    var failures: Int = 0,
    var total: Int = 0
)

class SubscriptionHealthClassifier(private val maxSamples: Int = 10) {
    private val nodes = HashMap<String, NodeProbeStats>()

    fun recordSample(nodeId: String, rttMs: Int, success: Boolean) {
        val stats = nodes.getOrPut(nodeId) { NodeProbeStats() }
        stats.total++
        if (success) {
            stats.samples.add(rttMs)
            if (stats.samples.size > maxSamples.coerceAtLeast(5)) {
                stats.samples.removeAt(0)
            }
        } else {
            stats.failures++
        }
    }

    fun classifyNode(nodeId: String): HealthTier {
        val stats = nodes[nodeId] ?: return HealthTier.TIER_F_DEAD
        if (stats.samples.isEmpty()) return HealthTier.TIER_F_DEAD

        val loss = stats.failures.toFloat() / stats.total.toFloat()
        val avgRtt = stats.samples.sum() / stats.samples.size

        return when {
            loss <= 0.05f && avgRtt <= 80 -> HealthTier.TIER_A_EXCELLENT
            loss <= 0.15f && avgRtt <= 200 -> HealthTier.TIER_B_GOOD
            loss <= 0.40f && avgRtt <= 600 -> HealthTier.TIER_C_DEGRADED
            else -> HealthTier.TIER_F_DEAD
        }
    }

    fun filterUsableNodes(minTier: HealthTier): List<String> {
        return nodes.keys.filter { classifyNode(it) >= minTier }
    }
}
