package com.luminet.android.scanner

import java.net.InetAddress
import java.nio.ByteBuffer
import java.nio.ByteOrder

/**
 * TCP Handshake Flow Latency & RTT Tracker.
 */
class FlowLatencyTracker {

    companion object {
        const val FNV_OFFSET_BASIS: ULong = 14695981039346656037uL
        const val FNV_PRIME: ULong = 1099511628211uL

        fun fnv1aHash(data: ByteArray): ULong {
            var h = FNV_OFFSET_BASIS
            for (b in data) {
                h = h xor (b.toUByte().toULong())
                h *= FNV_PRIME
            }
            return h
        }

        fun computeFlowHash(
            srcIp: String,
            srcPort: Int,
            dstIp: String,
            dstPort: Int
        ): ULong {
            val srcAddr = InetAddress.getByName(srcIp).address
            val dstAddr = InetAddress.getByName(dstIp).address

            val src16 = to16ByteArray(srcAddr)
            val dst16 = to16ByteArray(dstAddr)

            val bufSrc = ByteArray(18)
            System.arraycopy(src16, 0, bufSrc, 0, 16)
            bufSrc[16] = ((srcPort ushr 8) and 0xff).toByte()
            bufSrc[17] = (srcPort and 0xff).toByte()

            val bufDst = ByteArray(18)
            System.arraycopy(dst16, 0, bufDst, 0, 16)
            bufDst[16] = ((dstPort ushr 8) and 0xff).toByte()
            bufDst[17] = (dstPort and 0xff).toByte()

            val hSrc = fnv1aHash(bufSrc)
            val hDst = fnv1aHash(bufDst)

            return (hSrc + hDst) * FNV_PRIME
        }

        private fun to16ByteArray(addr: ByteArray): ByteArray {
            if (addr.size == 16) return addr
            if (addr.size == 4) {
                val out = ByteArray(16)
                out[10] = 0xff.toByte()
                out[11] = 0xff.toByte()
                System.arraycopy(addr, 0, out, 12, 4)
                return out
            }
            return ByteArray(16)
        }
    }

    data class TcpProbePacket(
        val srcIp: String,
        val srcPort: Int,
        val dstIp: String,
        val dstPort: Int,
        val syn: Boolean,
        val ack: Boolean,
        val timestampNanos: ULong
    ) {
        companion object {
            fun fromRawEvent(bytes: ByteArray): TcpProbePacket? {
                if (bytes.size < 48) return null

                val srcBytes = ByteArray(16)
                val dstBytes = ByteArray(16)
                System.arraycopy(bytes, 0, srcBytes, 0, 16)
                System.arraycopy(bytes, 16, dstBytes, 0, 16)

                val srcIp = parseIpFrom16(srcBytes)
                val dstIp = parseIpFrom16(dstBytes)

                val buffer = ByteBuffer.wrap(bytes)
                val srcPort = buffer.getShort(32).toInt() and 0xffff
                val dstPort = buffer.getShort(34).toInt() and 0xffff

                val syn = bytes[36].toInt() == 1
                val ack = bytes[37].toInt() == 1

                buffer.order(ByteOrder.LITTLE_ENDIAN)
                val ts = buffer.getLong(40).toULong()

                return TcpProbePacket(
                    srcIp = srcIp,
                    srcPort = srcPort,
                    dstIp = dstIp,
                    dstPort = dstPort,
                    syn = syn,
                    ack = ack,
                    timestampNanos = ts
                )
            }

            private fun parseIpFrom16(b: ByteArray): String {
                val isMapped = (0..9).all { b[it].toInt() == 0 } &&
                        b[10].toUByte() == 0xff.toUByte() &&
                        b[11].toUByte() == 0xff.toUByte()
                return if (isMapped) {
                    "${b[12].toUByte()}.${b[13].toUByte()}.${b[14].toUByte()}.${b[15].toUByte()}"
                } else {
                    InetAddress.getByAddress(b).hostAddress ?: ""
                }
            }
        }
    }

    data class FlowLatencyStats(
        var sampleCount: Long = 0,
        var minRttMs: Double? = null,
        var maxRttMs: Double? = null,
        var totalRttMs: Double = 0.0
    ) {
        fun record(rttMs: Double) {
            sampleCount++
            totalRttMs += rttMs
            minRttMs = minRttMs?.let { minOf(it, rttMs) } ?: rttMs
            maxRttMs = maxRttMs?.let { maxOf(it, rttMs) } ?: rttMs
        }

        fun averageRttMs(): Double? {
            return if (sampleCount == 0L) null else totalRttMs / sampleCount.toDouble()
        }
    }

    private val synTable = mutableMapOf<ULong, ULong>()
    val stats = FlowLatencyStats()

    @Synchronized
    fun onSyn(srcIp: String, srcPort: Int, dstIp: String, dstPort: Int, tsNanos: ULong) {
        val key = computeFlowHash(srcIp, srcPort, dstIp, dstPort)
        synTable[key] = tsNanos
    }

    @Synchronized
    fun onSynAck(srcIp: String, srcPort: Int, dstIp: String, dstPort: Int, tsNanos: ULong): Double? {
        val key = computeFlowHash(srcIp, srcPort, dstIp, dstPort)
        val synTs = synTable.remove(key) ?: return null
        if (tsNanos < synTs) return null

        val diffNanos = (tsNanos - synTs).toDouble()
        val rttMs = diffNanos / 1_000_000.0
        stats.record(rttMs)
        return rttMs
    }

    @Synchronized
    fun processPacket(pkt: TcpProbePacket): Double? {
        return when {
            pkt.syn && !pkt.ack -> {
                onSyn(pkt.srcIp, pkt.srcPort, pkt.dstIp, pkt.dstPort, pkt.timestampNanos)
                null
            }
            pkt.syn && pkt.ack -> {
                onSynAck(pkt.srcIp, pkt.srcPort, pkt.dstIp, pkt.dstPort, pkt.timestampNanos)
            }
            else -> null
        }
    }

    @Synchronized
    fun pruneStale(nowNanos: ULong, maxAgeNanos: ULong): Int {
        val before = synTable.size
        val toRemove = synTable.filter { (nowNanos > it.value) && (nowNanos - it.value > maxAgeNanos) }.keys
        toRemove.forEach { synTable.remove(it) }
        return before - synTable.size
    }

    @Synchronized
    fun pendingCount(): Int = synTable.size
}
