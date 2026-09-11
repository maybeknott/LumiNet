package com.luminet.android.tunnel

enum class CarrierType {
    TELECOM,
    UNICOM,
    MOBILE,
    SATELLITE,
    OVERLAY
}

data class CarrierRoute(
    val carrier: CarrierType,
    val endpoint: String,
    var latencyMs: Int,
    var packetLoss: Float,
    val weight: Int,
    var isActive: Boolean = true,
    var consecutiveFailures: Int = 0
)

class MulticarrierRelayChannel {
    private val routes = ArrayList<CarrierRoute>()

    fun addRoute(route: CarrierRoute) {
        routes.add(route)
    }

    fun selectBestCarrier(): CarrierRoute? {
        val active = routes.filter { it.isActive }
        return active.maxByOrNull { score(it) }
    }

    fun recordFeedback(carrier: CarrierType, rttMs: Int, success: Boolean) {
        for (r in routes) {
            if (r.carrier == carrier) {
                if (success) {
                    r.consecutiveFailures = 0
                    r.latencyMs = (r.latencyMs * 3 + rttMs) / 4
                    r.packetLoss *= 0.8f
                    r.isActive = true
                } else {
                    r.consecutiveFailures++
                    r.packetLoss = (r.packetLoss * 0.8f) + 0.2f
                    if (r.consecutiveFailures >= 3) {
                        r.isActive = false
                    }
                }
            }
        }
    }

    fun failoverSequence(): List<CarrierRoute> {
        return routes.sortedByDescending { score(it) }
    }

    private fun score(r: CarrierRoute): Double {
        val lat = r.latencyMs.coerceAtLeast(1).toDouble()
        val loss = r.packetLoss.toDouble()
        val fails = r.consecutiveFailures.toDouble()
        return r.weight.toDouble() / (lat * (1.0 + loss * 5.0) * (1.0 + fails * 2.0))
    }
}
