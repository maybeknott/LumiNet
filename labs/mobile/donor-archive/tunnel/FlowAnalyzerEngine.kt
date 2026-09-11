package com.luminet.android.tunnel

import java.util.concurrent.ConcurrentHashMap
import java.util.concurrent.atomic.AtomicLong

enum class FlowProtocol {
    UNKNOWN,
    TLS,
    HTTP,
    SSH,
    WIREGUARD,
    QUIC
}

data class FlowRecord(
    val flowId: Long,
    val src: String,
    val dst: String,
    val protocol: FlowProtocol,
    var packetsSent: Long = 1,
    var packetsRecv: Long = 0,
    var bytesSent: Long = 0,
    var bytesRecv: Long = 0,
    var retransmissions: Long = 0,
    val startTime: Long = System.currentTimeMillis(),
    var lastSeen: Long = System.currentTimeMillis()
) {
    fun retransmissionRate(): Double {
        if (packetsSent == 0L) return 0.0
        return (retransmissions.toDouble() / packetsSent.toDouble()) * 100.0
    }
}

class FlowAnalyzerEngine {
    private val flows = ConcurrentHashMap<Long, FlowRecord>()
    private val nextFlowId = AtomicLong(1L)

    companion object {
        fun inspectPayload(payload: ByteArray): FlowProtocol {
            if (payload.isEmpty()) return FlowProtocol.UNKNOWN
            if (payload.size >= 3 && payload[0] == 0x16.toByte() && payload[1] == 0x03.toByte()) {
                return FlowProtocol.TLS
            }
            val str = String(payload.take(8).toByteArray(), Charsets.US_ASCII)
            if (str.startsWith("GET ") || str.startsWith("POST ") || str.startsWith("HTTP")) {
                return FlowProtocol.HTTP
            }
            if (str.startsWith("SSH-")) {
                return FlowProtocol.SSH
            }
            if (payload.size >= 4 && (payload[0] == 0x01.toByte() || payload[0] == 0x02.toByte()) &&
                payload[1] == 0.toByte() && payload[2] == 0.toByte() && payload[3] == 0.toByte()
            ) {
                return FlowProtocol.WIREGUARD
            }
            return FlowProtocol.UNKNOWN
        }
    }

    fun registerFlow(src: String, dst: String, payload: ByteArray): Long {
        val fid = nextFlowId.getAndIncrement()
        val proto = inspectPayload(payload)
        val rec = FlowRecord(
            flowId = fid,
            src = src,
            dst = dst,
            protocol = proto,
            bytesSent = payload.size.toLong()
        )
        flows[fid] = rec
        return fid
    }

    fun recordPacket(flowId: Long, bytes: Long, isEgress: Boolean, isRetransmission: Boolean) {
        flows[flowId]?.let { f ->
            f.lastSeen = System.currentTimeMillis()
            if (isEgress) {
                f.packetsSent++
                f.bytesSent += bytes
                if (isRetransmission) f.retransmissions++
            } else {
                f.packetsRecv++
                f.bytesRecv += bytes
            }
        }
    }

    fun getFlow(flowId: Long): FlowRecord? = flows[flowId]

    fun detectAnomalies(maxRetransmissionRate: Double): List<Long> {
        return flows.values
            .filter { it.retransmissionRate() > maxRetransmissionRate }
            .map { it.flowId }
    }
}
