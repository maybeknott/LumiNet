// Copyright 2024-2026 LumiNet Authors. All Rights Reserved.
package com.luminet.android.tunnel

import java.nio.ByteBuffer

data class DnsTunnelFrame(
    val sessionId: Int,
    val sequence: Int,
    val isFinal: Boolean,
    val payload: ByteArray
)

object DnsTunnelCodec {
    fun encodeToQuery(frame: DnsTunnelFrame, domainSuffix: String): String {
        val buf = ByteBuffer.allocate(5 + frame.payload.size)
        buf.putShort(frame.sessionId.toShort())
        buf.putShort(frame.sequence.toShort())
        buf.put(if (frame.isFinal) 1.toByte() else 0.toByte())
        buf.put(frame.payload)

        val hex = buf.array().joinToString("") { "%02x".format(it) }
        return "$hex.$domainSuffix"
    }

    fun decodeFromQuery(query: String, domainSuffix: String): DnsTunnelFrame? {
        if (!query.endsWith(domainSuffix)) return null
        val trimmed = query.removeSuffix(domainSuffix).removeSuffix(".")
        val label = trimmed.split(".").firstOrNull() ?: return null
        if (label.length < 10 || label.length % 2 != 0) return null

        val bytes = ByteArray(label.length / 2)
        for (i in bytes.indices) {
            bytes[i] = label.substring(i * 2, i * 2 + 2).toInt(16).toByte()
        }

        val buf = ByteBuffer.wrap(bytes)
        val sess = buf.short.toInt() and 0xFFFF
        val seq = buf.short.toInt() and 0xFFFF
        val isFinal = buf.get() == 1.toByte()
        val payload = ByteArray(buf.remaining())
        buf.get(payload)

        return DnsTunnelFrame(sess, seq, isFinal, payload)
    }
}
