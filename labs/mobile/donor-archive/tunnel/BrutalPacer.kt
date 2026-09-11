// Copyright 2024-2026 LumiNet Authors. All Rights Reserved.
package com.luminet.android.tunnel

class BrutalPacer(
    var targetBps: Long,
    val minBps: Long = 1_000_000,
    val maxBps: Long = 100_000_000
) {
    private val lock = Any()

    fun updateAckFeedback(ackRateBps: Long, lossRatio: Double): Long = synchronized(lock) {
        val boundedLoss = lossRatio.coerceIn(0.0, 1.0)
        // R = AckRate * (1 + loss)
        val compensation = (ackRateBps.toDouble() * (1.0 + boundedLoss)).toLong()
        targetBps = compensation.coerceIn(minBps, maxBps)
        targetBps
    }

    fun getPacingDelayNanos(packetBytes: Int): Long = synchronized(lock) {
        if (targetBps <= 0) return 0L
        ((packetBytes.toLong() * 8.0 * 1_000_000_000L) / targetBps).toLong()
    }
}

class SalamanderObfuscator(private val key: ByteArray) {
    private var pos = 0

    fun applyInPlace(data: ByteArray) {
        for (i in data.indices) {
            data[i] = (data[i].toInt() xor key[pos % key.size].toInt()).toByte()
            pos++
        }
    }
}
