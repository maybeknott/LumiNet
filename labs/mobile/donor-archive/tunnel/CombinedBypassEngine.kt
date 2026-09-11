package com.luminet.android.tunnel

/**
 * Combined Multi-Layer DPI Bypass Engine for Android clients.
 * Combines low-TTL decoy probes and SNI-split fragmentation with micro-delays.
 * Unified from SNISPF-main into LumiNet.
 */
object CombinedBypassEngine {

    enum class BypassMode {
        DIRECT,
        FAKE_SNI_DECOY,
        SNI_FRAGMENT,
        COMBINED_TTL_DECOY,
        COMBINED_RAW_DESYNC
    }

    data class CombinedBypassConfig(
        val mode: BypassMode = BypassMode.COMBINED_TTL_DECOY,
        val fakeSni: String = "auth.vercel.com",
        val useTtlTrick: Boolean = true,
        val ttlHops: Int = 2,
        val fragmentStrategy: String = "sni_split",
        val fragmentDelayMs: Long = 10L
    )

    data class DecoyProbeSpec(
        val ttl: Int,
        val payload: ByteArray
    ) {
        override fun equals(other: Any?): Boolean {
            if (this === other) return true
            if (javaClass != other?.javaClass) return false
            other as DecoyProbeSpec
            return ttl == other.ttl && payload.contentEquals(other.payload)
        }

        override fun hashCode(): Int {
            return 31 * ttl + payload.contentHashCode()
        }
    }

    data class FragmentSpec(
        val payload: ByteArray,
        val delayMs: Long
    ) {
        override fun equals(other: Any?): Boolean {
            if (this === other) return true
            if (javaClass != other?.javaClass) return false
            other as FragmentSpec
            return delayMs == other.delayMs && payload.contentEquals(other.payload)
        }

        override fun hashCode(): Int {
            return 31 * delayMs.hashCode() + payload.contentHashCode()
        }
    }

    data class PreparedEvasionPlan(
        val decoyProbe: DecoyProbeSpec?,
        val fragments: List<FragmentSpec>
    )

    /**
     * Builds a prepared evasion sequence from a real ClientHello and decoy payload.
     */
    fun plan(
        realHello: ByteArray,
        fakeHello: ByteArray,
        config: CombinedBypassConfig = CombinedBypassConfig()
    ): PreparedEvasionPlan {
        val decoyProbe = if (config.useTtlTrick || config.mode == BypassMode.COMBINED_TTL_DECOY) {
            val ttl = if (config.ttlHops > 0) config.ttlHops else 2
            DecoyProbeSpec(ttl = ttl, payload = fakeHello.clone())
        } else {
            null
        }

        val fragments = mutableListOf<FragmentSpec>()
        if (realHello.isEmpty()) {
            return PreparedEvasionPlan(decoyProbe, fragments)
        }

        var splitPos = realHello.size / 2
        if (splitPos == 0) splitPos = 1

        if (config.fragmentStrategy == "sni_split" && realHello.size > 50) {
            splitPos = 43
        }

        if (realHello.size > 1 && splitPos < realHello.size) {
            fragments.add(FragmentSpec(realHello.copyOfRange(0, splitPos), 0L))
            fragments.add(FragmentSpec(realHello.copyOfRange(splitPos, realHello.size), config.fragmentDelayMs))
        } else {
            fragments.add(FragmentSpec(realHello.clone(), 0L))
        }

        return PreparedEvasionPlan(decoyProbe, fragments)
    }

    data class DomainEvaluationResult(
        val domain: String,
        val mode: BypassMode,
        val success: Boolean,
        val latencyMs: Long,
        val httpStatus: Int? = null,
        val error: String? = null
    )

    /**
     * Evaluates domain test results and selects the optimal bypass mode.
     */
    fun selectOptimalMode(results: List<DomainEvaluationResult>): BypassMode? {
        val hierarchy = listOf(
            BypassMode.DIRECT,
            BypassMode.SNI_FRAGMENT,
            BypassMode.FAKE_SNI_DECOY,
            BypassMode.COMBINED_TTL_DECOY,
            BypassMode.COMBINED_RAW_DESYNC
        )

        for (mode in hierarchy) {
            if (results.any { it.mode == mode && it.success }) {
                return mode
            }
        }
        return null
    }

    /**
     * Reconstructs payload from fragments to ensure zero data corruption.
     */
    fun reconstructPayload(plan: PreparedEvasionPlan): ByteArray {
        val totalLen = plan.fragments.sumOf { it.payload.size }
        val out = ByteArray(totalLen)
        var offset = 0
        for (f in plan.fragments) {
            System.arraycopy(f.payload, 0, out, offset, f.payload.size)
            offset += f.payload.size
        }
        return out
    }
}
