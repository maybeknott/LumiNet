package com.luminet.android.tunnel

data class EgressRoute(
    val id: String,
    val endpoint: String,
    val weight: Int,
    var currentWeight: Int = 0,
    var healthy: Boolean = true
)

class WeightedEgressRouter {
    private val routes = mutableListOf<EgressRoute>()

    fun addRoute(id: String, endpoint: String, weight: Int) {
        routes.add(EgressRoute(id, endpoint, weight))
    }

    fun setHealth(id: String, healthy: Boolean) {
        routes.find { it.id == id }?.let {
            it.healthy = healthy
            if (!healthy) it.currentWeight = 0
        }
    }

    fun nextRoute(): String? {
        val totalHealthyWeight = routes.filter { it.healthy && it.weight > 0 }.sumOf { it.weight }
        if (totalHealthyWeight <= 0) return null

        var best: EgressRoute? = null
        var maxWeight = Int.MIN_VALUE

        for (r in routes) {
            if (!r.healthy || r.weight <= 0) continue
            r.currentWeight += r.weight
            if (r.currentWeight > maxWeight) {
                maxWeight = r.currentWeight
                best = r
            }
        }

        return best?.let {
            it.currentWeight -= totalHealthyWeight
            it.endpoint
        }
    }
}
