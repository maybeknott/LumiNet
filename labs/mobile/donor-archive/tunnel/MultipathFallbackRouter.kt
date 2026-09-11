// Copyright 2024-2026 LumiNet Authors. All Rights Reserved.
package com.luminet.android.tunnel

enum class FallbackTierType {
    DIRECT,
    DOMAIN_FRONTED,
    ENCRYPTED_TUNNEL,
    QUIC_FALLBACK
}

data class FallbackTier(
    val type: FallbackTierType,
    var consecutiveFailures: Int = 0,
    val maxFailures: Int = 3
)

class MultipathFallbackRouter {
    private val tiers = mutableListOf<FallbackTier>()
    private val lock = Any()

    init {
        tiers.add(FallbackTier(FallbackTierType.DIRECT, 0, 2))
        tiers.add(FallbackTier(FallbackTierType.DOMAIN_FRONTED, 0, 3))
        tiers.add(FallbackTier(FallbackTierType.ENCRYPTED_TUNNEL, 0, 3))
        tiers.add(FallbackTier(FallbackTierType.QUIC_FALLBACK, 0, 5))
    }

    fun selectActiveTier(): FallbackTierType? = synchronized(lock) {
        tiers.firstOrNull { it.consecutiveFailures < it.maxFailures }?.type
    }

    fun recordSuccess(type: FallbackTierType) = synchronized(lock) {
        tiers.find { it.type == type }?.consecutiveFailures = 0
    }

    fun recordFailure(type: FallbackTierType) = synchronized(lock) {
        tiers.find { it.type == type }?.let { it.consecutiveFailures++ }
    }

    fun resetCircuitBreakers() = synchronized(lock) {
        tiers.forEach { it.consecutiveFailures = 0 }
    }
}
