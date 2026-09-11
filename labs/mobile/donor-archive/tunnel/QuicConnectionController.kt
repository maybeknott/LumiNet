package com.luminet.android.tunnel

import kotlin.math.abs
import kotlin.math.max

enum class QuicConnectionState {
    IDLE,
    HANDSHAKING,
    ESTABLISHED,
    CLOSING,
    CLOSED
}

data class QuicConnectionMetrics(
    val state: QuicConnectionState,
    val smoothedRttMs: Int,
    val rttVarMs: Int,
    val minRttMs: Int,
    val cwndBytes: Long,
    val bytesInFlight: Long,
    val lostPacketCount: Long
)

class QuicConnectionController(initialWindowBytes: Long = 14720) {
    var state: QuicConnectionState = QuicConnectionState.IDLE
    var smoothedRttMs: Int = 100
        private set
    var rttVarMs: Int = 50
        private set
    var minRttMs: Int = Int.MAX_VALUE
        private set
    var cwndBytes: Long = initialWindowBytes.coerceAtLeast(14720)
        private set
    var bytesInFlight: Long = 0
        private set
    var lostPacketCount: Long = 0
        private set
    private var ssthreshBytes: Long = Long.MAX_VALUE

    private data class SentRecord(val size: Int, val timeSentMs: Long)
    private val sentPackets = HashMap<Long, SentRecord>()

    fun canSend(size: Int): Boolean {
        return state == QuicConnectionState.ESTABLISHED && (bytesInFlight + size <= cwndBytes)
    }

    fun onPacketSent(pktNum: Long, size: Int, timeSentMs: Long) {
        bytesInFlight += size
        sentPackets[pktNum] = SentRecord(size, timeSentMs)
    }

    fun onAckReceived(pktNum: Long, nowMs: Long) {
        val rec = sentPackets.remove(pktNum) ?: return
        bytesInFlight = (bytesInFlight - rec.size).coerceAtLeast(0)

        if (nowMs >= rec.timeSentMs) {
            val sampleRtt = (nowMs - rec.timeSentMs).toInt()
            updateRtt(sampleRtt)
        }

        if (cwndBytes < ssthreshBytes) {
            cwndBytes += rec.size
        } else {
            val inc = (1472L * 1472L) / cwndBytes
            cwndBytes += max(1L, inc)
        }
    }

    fun onPacketLoss(pktNum: Long) {
        val rec = sentPackets.remove(pktNum) ?: return
        bytesInFlight = (bytesInFlight - rec.size).coerceAtLeast(0)
        lostPacketCount++

        ssthreshBytes = max(14720L, cwndBytes / 2)
        cwndBytes = ssthreshBytes
    }

    fun calculatePtoMs(): Int {
        return smoothedRttMs + max(10, 4 * rttVarMs)
    }

    fun getMetrics(): QuicConnectionMetrics {
        return QuicConnectionMetrics(
            state = state,
            smoothedRttMs = smoothedRttMs,
            rttVarMs = rttVarMs,
            minRttMs = if (minRttMs == Int.MAX_VALUE) 0 else minRttMs,
            cwndBytes = cwndBytes,
            bytesInFlight = bytesInFlight,
            lostPacketCount = lostPacketCount
        )
    }

    private fun updateRtt(sample: Int) {
        if (minRttMs == Int.MAX_VALUE) {
            minRttMs = sample
            smoothedRttMs = sample
            rttVarMs = sample / 2
        } else {
            if (sample < minRttMs) minRttMs = sample
            val diff = abs(sample - smoothedRttMs)
            rttVarMs = (3 * rttVarMs + diff) / 4
            smoothedRttMs = (7 * smoothedRttMs + sample) / 8
        }
    }
}
