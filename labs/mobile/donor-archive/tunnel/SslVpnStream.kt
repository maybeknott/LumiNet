// Copyright 2024-2026 LumiNet Authors. All Rights Reserved.
package com.luminet.android.tunnel

import java.nio.ByteBuffer

data class SslVpnFrame(
    val sessionId: Int,
    val payload: ByteArray
) {
    fun encode(): ByteArray {
        val buf = ByteBuffer.allocate(12 + payload.size)
        buf.putInt(0x53534C56) // 'SSLV'
        buf.putInt(sessionId)
        buf.putInt(payload.size)
        buf.put(payload)
        return buf.array()
    }

    companion object {
        fun decode(data: ByteArray): SslVpnFrame? {
            if (data.size < 12) return null
            val buf = ByteBuffer.wrap(data)
            val magic = buf.int
            if (magic != 0x53534C56) return null
            val sess = buf.int
            val len = buf.int
            if (buf.remaining() < len) return null
            val payload = ByteArray(len)
            buf.get(payload)
            return SslVpnFrame(sess, payload)
        }
    }
}
