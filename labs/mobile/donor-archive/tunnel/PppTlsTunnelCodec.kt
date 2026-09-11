package com.luminet.android.tunnel

import java.nio.ByteBuffer

class PppTlsTunnelCodec(val enableHdlc: Boolean = true) {

    fun encodeFrame(proto: Short, payload: ByteArray): ByteArray {
        val hdlcLen = if (enableHdlc) 2 else 0
        val bodyLen = hdlcLen + 2 + payload.size
        val buf = ByteBuffer.allocate(2 + bodyLen)

        buf.putShort(bodyLen.toShort())
        if (enableHdlc) {
            buf.put(0xFF.toByte())
            buf.put(0x03.toByte())
        }
        buf.putShort(proto)
        buf.put(payload)
        return buf.array()
    }

    fun decodeFrame(data: ByteArray): Pair<Short, ByteArray>? {
        if (data.size < 2) return null
        val buf = ByteBuffer.wrap(data)
        val bodyLen = buf.getShort().toInt() and 0xFFFF
        if (data.size < 2 + bodyLen) return null

        var offset = 0
        if (enableHdlc) {
            if (bodyLen < 2) return null
            val b0 = buf.get().toInt() and 0xFF
            val b1 = buf.get().toInt() and 0xFF
            if (b0 != 0xFF || b1 != 0x03) return null
            offset += 2
        }

        if (bodyLen < offset + 2) return null
        val proto = buf.getShort()
        val payloadLen = bodyLen - offset - 2
        val payload = ByteArray(payloadLen)
        buf.get(payload)
        return Pair(proto, payload)
    }
}
