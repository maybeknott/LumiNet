package com.luminet.android.tunnel

data class ServerlessFrame(
    val streamId: Int,
    val isEof: Boolean,
    val payload: ByteArray
)

class ServerlessTunnelCarrier {
    val magic: Int = 0x534c5353 // "SLSS"

    fun encode(frame: ServerlessFrame): ByteArray {
        val size = 4 + 4 + 1 + 4 + frame.payload.size
        val out = ByteArray(size)
        // Magic
        out[0] = (magic ushr 24).toByte()
        out[1] = (magic ushr 16).toByte()
        out[2] = (magic ushr 8).toByte()
        out[3] = magic.toByte()
        // Stream ID
        out[4] = (frame.streamId ushr 24).toByte()
        out[5] = (frame.streamId ushr 16).toByte()
        out[6] = (frame.streamId ushr 8).toByte()
        out[7] = frame.streamId.toByte()
        // EOF flag
        out[8] = if (frame.isEof) 1 else 0
        // Length
        val len = frame.payload.size
        out[9] = (len ushr 24).toByte()
        out[10] = (len ushr 16).toByte()
        out[11] = (len ushr 8).toByte()
        out[12] = len.toByte()
        // Payload
        System.arraycopy(frame.payload, 0, out, 13, len)
        return out
    }

    fun decode(bytes: ByteArray): ServerlessFrame {
        if (bytes.size < 13) throw IllegalArgumentException("frame too short")
        val streamId = ((bytes[4].toInt() and 0xFF) shl 24) or
                       ((bytes[5].toInt() and 0xFF) shl 16) or
                       ((bytes[6].toInt() and 0xFF) shl 8) or
                       (bytes[7].toInt() and 0xFF)
        val isEof = bytes[8].toInt() == 1
        val len = ((bytes[9].toInt() and 0xFF) shl 24) or
                  ((bytes[10].toInt() and 0xFF) shl 16) or
                  ((bytes[11].toInt() and 0xFF) shl 8) or
                  (bytes[12].toInt() and 0xFF)
        val payload = ByteArray(len)
        System.arraycopy(bytes, 13, payload, 0, len.coerceAtMost(bytes.size - 13))
        return ServerlessFrame(streamId, isEof, payload)
    }
}
