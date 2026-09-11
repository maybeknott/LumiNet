package com.luminet.android.tunnel

/**
 * Serverless Direct Shaper & Zero-VPS Evasion Engine for Android clients.
 * Shapes ClientHello and TCP stream traffic directly to destinations without requiring a remote VPS.
 * Originates from Serverless-for-Iran-main and unified into LumiNet.
 */
object ServerlessDirectShaper {

    enum class ServerlessProfile {
        LOW_DELAY,
        HIGH_DELAY
    }

    data class ShaperFragment(
        val payload: ByteArray,
        val delayMs: Long
    ) {
        override fun equals(other: Any?): Boolean {
            if (this === other) return true
            if (javaClass != other?.javaClass) return false
            other as ShaperFragment
            return delayMs == other.delayMs && payload.contentEquals(other.payload)
        }

        override fun hashCode(): Int {
            return 31 * delayMs.hashCode() + payload.contentHashCode()
        }
    }

    data class ServerlessShaperConfig(
        val profile: ServerlessProfile = ServerlessProfile.LOW_DELAY,
        val tlsRecordSplit: Int = 5,
        val sniSplitOffset: Int = 43,
        val maxSplitTls: Int = 522,
        val maxSplitTcp: Int = 419,
        val happyEyeballsIpv6First: Boolean = true,
        val udpNoiseEnabled: Boolean = true,
        val udpNoiseMinLen: Int = 1200,
        val udpNoiseMaxLen: Int = 1230,
        val udpNoiseResetInterval: Int = 28
    )

    /**
     * Detects Iranian national censorship redirection landing sinks:
     * - IPv4: 10.10.34.0/24
     * - IPv6: 2001:4188:2:600::/64
     */
    fun isCensorshipSink(ipStr: String): Boolean {
        if (ipStr.startsWith("10.10.34.")) {
            return true
        }
        val lower = ipStr.lowercase()
        if (lower.startsWith("2001:4188:2:600:") || lower.startsWith("2001:4188:0002:0600:")) {
            return true
        }
        return false
    }

    /**
     * Shapes a TLS ClientHello packet across record boundaries, SNI offsets,
     * and 1-byte micro-fragments with profile-directed pacing.
     */
    fun shapeClientHello(payload: ByteArray, config: ServerlessShaperConfig = ServerlessShaperConfig()): List<ShaperFragment> {
        if (payload.isEmpty()) {
            return emptyList()
        }

        val recordSplit = if (config.tlsRecordSplit > 0) config.tlsRecordSplit else 5
        if (payload.size <= recordSplit) {
            return listOf(ShaperFragment(payload.clone(), 0L))
        }

        val fragments = mutableListOf<ShaperFragment>()

        // 1. Record header (0..recordSplit)
        fragments.add(ShaperFragment(payload.copyOfRange(0, recordSplit), 0L))
        var currOffset = recordSplit

        // 2. Prefix up to SNI boundary
        val sniBoundary = config.sniSplitOffset.coerceAtMost(payload.size)
        if (sniBoundary > currOffset) {
            fragments.add(ShaperFragment(payload.copyOfRange(currOffset, sniBoundary), calculateDelay(0, config.profile)))
            currOffset = sniBoundary
        }

        // 3. Remainder split into 1-byte chunks up to maxSplitTls
        var sliceIdx = 1
        val maxSplit = if (config.maxSplitTls > 0) config.maxSplitTls else 522

        while (currOffset < payload.size && currOffset < maxSplit) {
            val chunkLen = 1.coerceAtMost(payload.size - currOffset)
            val delay = calculateDelay(sliceIdx, config.profile)
            fragments.add(ShaperFragment(payload.copyOfRange(currOffset, currOffset + chunkLen), delay))
            currOffset += chunkLen
            sliceIdx++
        }

        // 4. Any leftover beyond maxSplit as final fragment
        if (currOffset < payload.size) {
            fragments.add(ShaperFragment(payload.copyOfRange(currOffset, payload.size), calculateDelay(sliceIdx, config.profile)))
        }

        return fragments
    }

    /**
     * Shapes generic TCP stream into 1-byte chunks up to maxSplitTcp.
     */
    fun shapeTcpStream(payload: ByteArray, config: ServerlessShaperConfig = ServerlessShaperConfig()): List<ShaperFragment> {
        if (payload.isEmpty()) return emptyList()

        val fragments = mutableListOf<ShaperFragment>()
        var currOffset = 0
        var sliceIdx = 0
        val maxSplit = if (config.maxSplitTcp > 0) config.maxSplitTcp else 419

        while (currOffset < payload.size && currOffset < maxSplit) {
            val chunkLen = 1.coerceAtMost(payload.size - currOffset)
            val delay = if (currOffset == 0) 0L else calculateDelay(sliceIdx, config.profile)
            fragments.add(ShaperFragment(payload.copyOfRange(currOffset, currOffset + chunkLen), delay))
            currOffset += chunkLen
            sliceIdx++
        }

        if (currOffset < payload.size) {
            fragments.add(ShaperFragment(payload.copyOfRange(currOffset, payload.size), calculateDelay(sliceIdx, config.profile)))
        }

        return fragments
    }

    /**
     * Computes fragment delay in ms for slice index based on profile.
     */
    fun calculateDelay(sliceIdx: Int, profile: ServerlessProfile): Long {
        return when (profile) {
            ServerlessProfile.LOW_DELAY -> 1L
            ServerlessProfile.HIGH_DELAY -> {
                if (sliceIdx > 0 && sliceIdx % 10 == 0) 400L else 1L
            }
        }
    }

    /**
     * Generates randomized UDP noise packet within configured length range.
     */
    fun generateUdpNoise(counter: Long, config: ServerlessShaperConfig = ServerlessShaperConfig()): ByteArray? {
        if (!config.udpNoiseEnabled) return null

        val minLen = if (config.udpNoiseMinLen > 0) config.udpNoiseMinLen else 1200
        val maxLen = if (config.udpNoiseMaxLen > minLen) config.udpNoiseMaxLen else minLen + 30
        val lenRange = maxLen - minLen
        val targetLen = minLen + ((counter * 7L) % lenRange.toLong()).toInt()

        val noise = ByteArray(targetLen)
        for (i in noise.indices) {
            noise[i] = ((counter.toInt() + i * 31) and 0xFF).toByte()
        }
        return noise
    }

    /**
     * Reconstructs contiguous bytes from shaped fragments.
     */
    fun reconstruct(fragments: List<ShaperFragment>): ByteArray {
        val total = fragments.sumOf { it.payload.size }
        val out = ByteArray(total)
        var offset = 0
        for (f in fragments) {
            System.arraycopy(f.payload, 0, out, offset, f.payload.size)
            offset += f.payload.size
        }
        return out
    }
}
