package com.luminet.android.tunnel

data class AndroidEgressTarget(
    val targetId: String,
    val protocol: String,
    val weight: Int,
    var latencyMs: Int,
    var lossPercent: Double,
    var isActive: Boolean = true
)

class MultiprotoEgressSelector {
    private val targets = mutableMapOf<String, AndroidEgressTarget>()

    fun addTarget(target: AndroidEgressTarget) {
        targets[target.targetId] = target
    }

    fun updateMetrics(targetId: String, latencyMs: Int, lossPercent: Double, isActive: Boolean) {
        val t = targets[targetId] ?: return
        t.latencyMs = latencyMs
        t.lossPercent = lossPercent
        t.isActive = isActive
    }

    fun selectBest(preferredProto: String? = null): AndroidEgressTarget? {
        var best: AndroidEgressTarget? = null
        var bestScore = -1e9

        for (t in targets.values) {
            if (!t.isActive) continue
            var score = (t.weight * 10.0) - t.latencyMs - (t.lossPercent * 20.0)
            if (preferredProto != null && t.protocol == preferredProto) {
                score += 50.0
            }
            if (score > bestScore) {
                bestScore = score
                best = t
            }
        }
        return best
    }
}
