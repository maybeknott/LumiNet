package com.luminet.android.tunnel

enum class AndroidPipelineTier {
    DIRECT_MESH,
    HOLE_PUNCHED_MESH,
    DPI_EVADED_MESH,
    STEALTH_BRIDGE_FALLBACK
}

data class AndroidPipelineMetrics(
    var packetsProcessed: Long = 0,
    var modeSwitches: Int = 0,
    var currentTier: AndroidPipelineTier = AndroidPipelineTier.DIRECT_MESH
)

class UniversalMeshEvasionPipeline(val peerId: String) {
    var consecutiveErrors: Int = 0
        private set
    val metrics = AndroidPipelineMetrics()

    val escalationThreshold: Int = 3

    fun processOutboundFrame(frame: ByteArray): List<ByteArray> {
        metrics.packetsProcessed++
        return when (metrics.currentTier) {
            AndroidPipelineTier.DIRECT_MESH, AndroidPipelineTier.HOLE_PUNCHED_MESH -> {
                listOf(frame)
            }
            AndroidPipelineTier.DPI_EVADED_MESH -> {
                if (frame.size > 8) {
                    val mid = frame.size / 2
                    listOf(frame.copyOfRange(0, mid), frame.copyOfRange(mid, frame.size))
                } else {
                    listOf(frame)
                }
            }
            AndroidPipelineTier.STEALTH_BRIDGE_FALLBACK -> {
                val prefix = "STH:".toByteArray(Charsets.UTF_8)
                val wrapped = ByteArray(prefix.size + frame.size)
                System.arraycopy(prefix, 0, wrapped, 0, prefix.size)
                System.arraycopy(frame, 0, wrapped, prefix.size, frame.size)
                listOf(wrapped)
            }
        }
    }

    fun reportFailure(): AndroidPipelineTier {
        consecutiveErrors++
        if (consecutiveErrors >= escalationThreshold) {
            consecutiveErrors = 0
            val nextTier = when (metrics.currentTier) {
                AndroidPipelineTier.DIRECT_MESH -> AndroidPipelineTier.HOLE_PUNCHED_MESH
                AndroidPipelineTier.HOLE_PUNCHED_MESH -> AndroidPipelineTier.DPI_EVADED_MESH
                AndroidPipelineTier.DPI_EVADED_MESH -> AndroidPipelineTier.STEALTH_BRIDGE_FALLBACK
                AndroidPipelineTier.STEALTH_BRIDGE_FALLBACK -> AndroidPipelineTier.STEALTH_BRIDGE_FALLBACK
            }

            if (nextTier != metrics.currentTier) {
                metrics.currentTier = nextTier
                metrics.modeSwitches++
            }
        }
        return metrics.currentTier
    }

    fun reportSuccess() {
        consecutiveErrors = 0
    }
}
