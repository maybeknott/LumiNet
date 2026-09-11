package com.luminet.android.tunnel

import kotlin.math.ln
import kotlin.math.max
import kotlin.math.min

data class AndroidDiversityNode(
    val nodeId: String,
    val asn: Long,
    val countryCode: String,
    val latencyMs: Int
)

data class AndroidDiversityMetrics(
    val totalNodes: Int,
    val uniqueAsns: Int,
    val uniqueCountries: Int,
    val diversityScore: Double
)

class NodeDiversitySampler {
    private val nodes = mutableMapOf<String, AndroidDiversityNode>()

    fun addNode(node: AndroidDiversityNode) {
        nodes[node.nodeId] = node
    }

    fun computeMetrics(): AndroidDiversityMetrics {
        if (nodes.isEmpty()) return AndroidDiversityMetrics(0, 0, 0, 0.0)

        val asnCounts = mutableMapOf<Long, Int>()
        val countryCounts = mutableMapOf<String, Int>()

        for (n in nodes.values) {
            asnCounts[n.asn] = (asnCounts[n.asn] ?: 0) + 1
            countryCounts[n.countryCode] = (countryCounts[n.countryCode] ?: 0) + 1
        }

        val total = nodes.size.toDouble()
        val log2 = ln(2.0)
        var entropy = 0.0
        for (count in asnCounts.values) {
            val p = count / total
            entropy -= p * (ln(p) / log2)
        }

        val maxEntropy = max(1.0, ln(total) / log2)
        val normEntropy = min(1.0, entropy / maxEntropy)
        val countryFactor = min(1.0, countryCounts.size / total)
        val score = min(100.0, normEntropy * 60.0 + countryFactor * 40.0)

        return AndroidDiversityMetrics(
            totalNodes = nodes.size,
            uniqueAsns = asnCounts.size,
            uniqueCountries = countryCounts.size,
            diversityScore = score
        )
    }

    fun sampleDiverseSubset(maxNodes: Int): List<String> {
        val sorted = nodes.values.sortedBy { it.latencyMs }
        val asnSeen = mutableSetOf<Long>()
        val sampled = mutableListOf<String>()

        // Pass 1: 1 per ASN
        for (n in sorted) {
            if (sampled.size >= maxNodes) break
            if (!asnSeen.contains(n.asn)) {
                asnSeen.add(n.asn)
                sampled.add(n.nodeId)
            }
        }

        // Pass 2: fill remaining
        for (n in sorted) {
            if (sampled.size >= maxNodes) break
            if (!sampled.contains(n.nodeId)) {
                sampled.add(n.nodeId)
            }
        }

        return sampled
    }
}
