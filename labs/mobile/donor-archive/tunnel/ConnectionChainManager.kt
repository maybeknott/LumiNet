package com.luminet.android.tunnel

enum class ChainSlot(val wireName: String) {
    Before("before"),
    Base("base"),
    After("after");
}

enum class HopMode(val wireName: String) {
    Off("off"),
    Automatic("automatic"),
    Fixed("fixed");
}

data class ChainProfileRef(
    val subscriptionId: String,
    val fingerprint: String,
    val name: String
)

data class ChainHop(
    val slot: ChainSlot,
    val mode: HopMode,
    val fixedRef: ChainProfileRef? = null
)

data class ChainSettings(
    val enabled: Boolean = false,
    val before: ChainHop = ChainHop(ChainSlot.Before, HopMode.Off),
    val after: ChainHop = ChainHop(ChainSlot.After, HopMode.Off)
)

data class ResolvedChain(
    val hops: List<ChainProfileRef>,
    val isChained: Boolean
)

object ConnectionChainManager {

    fun resolveChain(
        base: ChainProfileRef,
        settings: ChainSettings,
        available: List<ChainProfileRef> = emptyList()
    ): ResolvedChain {
        if (!settings.enabled) {
            return ResolvedChain(hops = listOf(base), isChained = false)
        }

        val hops = mutableListOf<ChainProfileRef>()
        var beforeResolved: ChainProfileRef? = null

        // 1. Resolve Before Hop
        when (settings.before.mode) {
            HopMode.Off -> {}
            HopMode.Fixed -> {
                val ref = requireNotNull(settings.before.fixedRef) { "Fixed before hop profile ref is null" }
                if (ref.fingerprint == base.fingerprint) {
                    throw IllegalStateException("Loop detected: before hop duplicates base fingerprint ${base.fingerprint}")
                }
                beforeResolved = ref
                hops.add(ref)
            }
            HopMode.Automatic -> {
                val candidate = available.firstOrNull { it.fingerprint != base.fingerprint }
                    ?: throw IllegalStateException("No distinct candidates available for before hop")
                beforeResolved = candidate
                hops.add(candidate)
            }
        }

        // 2. Add Base Hop
        hops.add(base)

        // 3. Resolve After Hop
        when (settings.after.mode) {
            HopMode.Off -> {}
            HopMode.Fixed -> {
                val ref = requireNotNull(settings.after.fixedRef) { "Fixed after hop profile ref is null" }
                if (ref.fingerprint == base.fingerprint) {
                    throw IllegalStateException("Loop detected: after hop duplicates base fingerprint ${base.fingerprint}")
                }
                if (beforeResolved != null && ref.fingerprint == beforeResolved.fingerprint) {
                    throw IllegalStateException("Loop detected: after hop duplicates before hop ${beforeResolved.fingerprint}")
                }
                hops.add(ref)
            }
            HopMode.Automatic -> {
                val candidate = available.firstOrNull {
                    it.fingerprint != base.fingerprint && (beforeResolved == null || it.fingerprint != beforeResolved.fingerprint)
                } ?: throw IllegalStateException("No distinct candidates available for after hop")
                hops.add(candidate)
            }
        }

        return ResolvedChain(
            hops = hops,
            isChained = hops.size > 1
        )
    }
}
