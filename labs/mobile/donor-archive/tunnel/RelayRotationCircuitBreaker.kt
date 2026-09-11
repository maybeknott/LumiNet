package com.luminet.android.tunnel

import java.util.concurrent.CopyOnWriteArrayList

enum class AndroidCircuitState {
    CLOSED,
    OPEN,
    HALF_OPEN
}

data class AndroidRelayNode(
    val id: String,
    val endpoint: String,
    var consecutiveFailures: Int = 0,
    var successfulProbes: Int = 0,
    var state: AndroidCircuitState = AndroidCircuitState.CLOSED,
    var lastStateChangeMs: Long = 0
)

data class AndroidCircuitBreakerConfig(
    val failureThreshold: Int = 3,
    val halfOpenProbesNeeded: Int = 2,
    val cooldownMs: Long = 30_000
)

class RelayRotationCircuitBreaker(val config: AndroidCircuitBreakerConfig = AndroidCircuitBreakerConfig()) {
    val relays = CopyOnWriteArrayList<AndroidRelayNode>()
    var currentIndex: Int = 0
        private set

    fun registerRelay(id: String, endpoint: String) {
        relays.add(AndroidRelayNode(id, endpoint))
    }

    fun selectActiveRelay(nowMs: Long): String? {
        val total = relays.size
        if (total == 0) return null

        for (i in 0 until total) {
            val idx = (currentIndex + i) % total
            val relay = relays[idx]

            if (relay.state == AndroidCircuitState.OPEN) {
                if (nowMs - relay.lastStateChangeMs >= config.cooldownMs) {
                    relay.state = AndroidCircuitState.HALF_OPEN
                    relay.successfulProbes = 0
                    relay.lastStateChangeMs = nowMs
                    currentIndex = idx
                    return relay.id
                }
            } else {
                currentIndex = idx
                return relay.id
            }
        }
        return null
    }

    fun recordSuccess(id: String, nowMs: Long) {
        val relay = relays.find { it.id == id } ?: return
        relay.consecutiveFailures = 0
        if (relay.state == AndroidCircuitState.HALF_OPEN) {
            relay.successfulProbes++
            if (relay.successfulProbes >= config.halfOpenProbesNeeded) {
                relay.state = AndroidCircuitState.CLOSED
                relay.lastStateChangeMs = nowMs
            }
        }
    }

    fun recordFailure(id: String, nowMs: Long) {
        val relay = relays.find { it.id == id } ?: return
        relay.consecutiveFailures++
        if (relay.state == AndroidCircuitState.CLOSED && relay.consecutiveFailures >= config.failureThreshold) {
            relay.state = AndroidCircuitState.OPEN
            relay.lastStateChangeMs = nowMs
            currentIndex = (currentIndex + 1) % relays.size
        } else if (relay.state == AndroidCircuitState.HALF_OPEN) {
            relay.state = AndroidCircuitState.OPEN
            relay.lastStateChangeMs = nowMs
            currentIndex = (currentIndex + 1) % relays.size
        }
    }
}
