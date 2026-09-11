package com.luminet.android.tunnel

import java.nio.ByteBuffer
import java.nio.charset.StandardCharsets

/**
 * RFC 8831 / RFC 8832 WebRTC DataChannel message framing and PPID values.
 */
object WebRtcDataChannelConstants {
    const val PPID_DCEP = 50L
    const val PPID_STRING = 51L
    const val PPID_BINARY = 53L
    const val PPID_STRING_EMPTY = 56L
    const val PPID_BINARY_EMPTY = 57L

    const val DCEP_MSG_ACK: Byte = 0x02
    const val DCEP_MSG_OPEN: Byte = 0x03
}

/**
 * DataChannel frame consisting of 4-byte big-endian PPID + payload bytes.
 */
data class WebRtcDataChannelFrame(
    val ppid: Long,
    val payload: ByteArray
) {
    fun encode(): ByteArray {
        val bb = ByteBuffer.allocate(4 + payload.size)
        bb.putInt((ppid and 0xFFFFFFFFL).toInt())
        bb.put(payload)
        return bb.array()
    }

    override fun equals(other: Any?): Boolean {
        if (this === other) return true
        if (javaClass != other?.javaClass) return false
        other as WebRtcDataChannelFrame
        if (ppid != other.ppid) return false
        if (!payload.contentEquals(other.payload)) return false
        return true
    }

    override fun hashCode(): Int {
        var result = ppid.hashCode()
        result = 31 * result + payload.contentHashCode()
        return result
    }

    companion object {
        fun binary(data: ByteArray): WebRtcDataChannelFrame {
            val ppid = if (data.isEmpty()) {
                WebRtcDataChannelConstants.PPID_BINARY_EMPTY
            } else {
                WebRtcDataChannelConstants.PPID_BINARY
            }
            return WebRtcDataChannelFrame(ppid, data)
        }

        fun string(text: String): WebRtcDataChannelFrame {
            val bytes = text.toByteArray(StandardCharsets.UTF_8)
            val ppid = if (bytes.isEmpty()) {
                WebRtcDataChannelConstants.PPID_STRING_EMPTY
            } else {
                WebRtcDataChannelConstants.PPID_STRING
            }
            return WebRtcDataChannelFrame(ppid, bytes)
        }

        fun decode(src: ByteArray): WebRtcDataChannelFrame {
            require(src.size >= 4) { "Buffer too short for WebRTC DataChannel frame" }
            val bb = ByteBuffer.wrap(src)
            val ppid = bb.int.toLong() and 0xFFFFFFFFL
            val payload = ByteArray(src.size - 4)
            bb.get(payload)
            return WebRtcDataChannelFrame(ppid, payload)
        }
    }
}
