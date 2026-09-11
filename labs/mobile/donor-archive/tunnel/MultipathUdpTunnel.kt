package com.luminet.android.tunnel

import java.nio.ByteBuffer
import java.util.concurrent.ConcurrentHashMap

enum class BondingMode {
    ROUND_ROBIN,
    LOWEST_LATENCY,
    WEIGHTED_LOSS
}

enum class PathState {
    ACTIVE,
    STANDBY,
    DEGRADED,
    DOWN
}

data class PathMetrics(
    val pathId: Int,
    val localAddr: String,
    val remoteAddr: String,
    var rttMs: Double = 0.0,
    var lossPercentage: Double = 0.0,
    var txBytes: Long = 0L,
    var rxBytes: Long = 0L,
    var state: PathState = PathState.ACTIVE,
    val weight: Int = 1
) {
    fun recordHeartbeat(latencyMs: Double, lost: Boolean) {
        rttMs = if (rttMs <= 0.0) latencyMs else rttMs * 0.8 + latencyMs * 0.2
        val sample = if (lost) 100.0 else 0.0
        lossPercentage = lossPercentage * 0.9 + sample * 0.1
        state = when {
            lossPercentage > 90.0 -> PathState.DOWN
            lossPercentage > 50.0 -> PathState.DEGRADED
            else -> PathState.ACTIVE
        }
    }
}

class MultipathUdpTunnel(
    val tunnelId: String,
    val mode: BondingMode
) {
    private val paths = ConcurrentHashMap<Int, PathMetrics>()
    private var rrCounter = 0

    fun addPath(metrics: PathMetrics) {
        paths[metrics.pathId] = metrics
    }

    fun removePath(pathId: Int): PathMetrics? = paths.remove(pathId)

    fun activePaths(): List<Int> = paths.values
        .filter { it.state == PathState.ACTIVE || it.state == PathState.DEGRADED }
        .map { it.pathId }

    fun selectPathForEgress(): Int? {
        val active = activePaths()
        if (active.isEmpty()) return null

        return when (mode) {
            BondingMode.ROUND_ROBIN -> {
                val chosen = active[rrCounter % active.size]
                rrCounter++
                chosen
            }
            BondingMode.LOWEST_LATENCY -> {
                active.minByOrNull { paths[it]?.rttMs ?: Double.MAX_VALUE } ?: active[0]
            }
            BondingMode.WEIGHTED_LOSS -> {
                active.maxByOrNull {
                    val p = paths[it] ?: return@maxByOrNull 0.0
                    p.weight * (100.0 - p.lossPercentage) / (p.rttMs.coerceAtLeast(1.0))
                } ?: active[0]
            }
        }
    }

    fun encapsulate(pathId: Int, payload: ByteArray): ByteArray? {
        val p = paths[pathId] ?: return null
        p.txBytes += payload.size

        val buf = ByteBuffer.allocate(7 + payload.size)
        buf.putInt(pathId)
        buf.putShort(payload.size.toShort())
        buf.put(0x01.toByte())
        buf.put(payload)
        return buf.array()
    }

    fun decapsulate(frame: ByteArray): Pair<Int, ByteArray>? {
        if (frame.size < 7) return null
        val buf = ByteBuffer.wrap(frame)
        val pathId = buf.int
        val len = buf.short.toInt() and 0xFFFF
        val _flags = buf.get()
        if (frame.size < 7 + len) return null

        val payload = ByteArray(len)
        buf.get(payload)
        paths[pathId]?.let { it.rxBytes += len }
        return Pair(pathId, payload)
    }
}
