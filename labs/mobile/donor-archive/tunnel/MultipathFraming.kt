package com.luminet.android.tunnel

import java.nio.ByteBuffer
import java.nio.ByteOrder

enum class MpFrameType(val code: Byte) {
    HELLO(0x01),
    HELLO_ACK(0x02),
    DATA(0x03),
    CLOSE(0x04),
    PING(0x05),
    PONG(0x06);

    companion object {
        fun fromCode(code: Byte): MpFrameType =
            entries.firstOrNull { it.code == code }
                ?: throw IllegalArgumentException("Unknown multipath frame type code: $code")
    }
}

data class MpFrame(
    val type: MpFrameType,
    val sessionId: ByteArray,
    val seq: Long,
    val payload: ByteArray
) {
    init {
        require(sessionId.size == 16) { "Session ID must be exactly 16 bytes" }
    }

    fun encode(): ByteArray {
        val buf = ByteBuffer.allocate(HEADER_SIZE + payload.size).order(ByteOrder.BIG_ENDIAN)
        buf.put(type.code)
        buf.put(sessionId)
        buf.putLong(seq)
        buf.putInt(payload.size)
        buf.put(payload)
        return buf.array()
    }

    companion object {
        const val HEADER_SIZE = 1 + 16 + 8 + 4 // 29 bytes

        fun decode(data: ByteArray): MpFrame {
            require(data.size >= HEADER_SIZE) { "Data too short for multipath frame header" }
            val buf = ByteBuffer.wrap(data).order(ByteOrder.BIG_ENDIAN)
            val type = MpFrameType.fromCode(buf.get())
            val sid = ByteArray(16)
            buf.get(sid)
            val seq = buf.getLong()
            val payloadLen = buf.getInt()
            require(payloadLen >= 0 && data.size >= HEADER_SIZE + payloadLen) {
                "Incomplete payload in multipath frame"
            }
            val payload = ByteArray(payloadLen)
            buf.get(payload)
            return MpFrame(type, sid, seq, payload)
        }
    }

    override fun equals(other: Any?): Boolean {
        if (this === other) return true
        if (javaClass != other?.javaClass) return false
        other as MpFrame
        if (type != other.type) return false
        if (!sessionId.contentEquals(other.sessionId)) return false
        if (seq != other.seq) return false
        if (!payload.contentEquals(other.payload)) return false
        return true
    }

    override fun hashCode(): Int {
        var result = type.hashCode()
        result = 31 * result + sessionId.contentHashCode()
        result = 31 * result + seq.hashCode()
        result = 31 * result + payload.contentHashCode()
        return result
    }
}

class InOrderDedupBuffer(
    startSeq: Long = 0L,
    private val capacity: Int = 1024
) {
    private var nextSeq = startSeq
    private val pending = mutableMapOf<Long, ByteArray>()

    @Synchronized
    fun push(seq: Long, payload: ByteArray): List<ByteArray> {
        if (seq < nextSeq || pending.containsKey(seq)) {
            return emptyList()
        }
        if (pending.size >= capacity) {
            throw IllegalStateException("Dedup buffer capacity exceeded")
        }

        pending[seq] = payload
        val deliverable = mutableListOf<ByteArray>()

        while (pending.containsKey(nextSeq)) {
            val p = pending.remove(nextSeq)!!
            deliverable.add(p)
            nextSeq++
        }
        return deliverable
    }

    @Synchronized
    fun nextSeq(): Long = nextSeq
}
