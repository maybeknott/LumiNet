// Copyright 2024-2026 LumiNet Authors. All Rights Reserved.
package com.luminet.android.tunnel

import java.nio.ByteBuffer
import java.nio.charset.StandardCharsets
import java.security.SecureRandom

enum class BrookTargetType(val code: Byte) {
    IPV4(1),
    DOMAIN(2),
    IPV6(3)
}

data class BrookRequest(
    val targetType: BrookTargetType,
    val host: String,
    val port: Int
)

object BrookStreamCodec {
    fun encodeRequest(req: BrookRequest): ByteArray {
        val nonce = ByteArray(8)
        SecureRandom().nextBytes(nonce)

        val hostBytes = req.host.toByteArray(StandardCharsets.UTF_8)
        val buf = ByteBuffer.allocate(8 + 1 + 1 + hostBytes.size + 2)
        buf.put(nonce)
        buf.put(req.targetType.code)
        buf.put(hostBytes.size.toByte())
        buf.put(hostBytes)
        buf.putShort(req.port.toShort())
        return buf.array()
    }

    fun decodeRequest(data: ByteArray): BrookRequest? {
        if (data.size < 12) return null
        val buf = ByteBuffer.wrap(data)
        val nonce = ByteArray(8)
        buf.get(nonce)
        val code = buf.get()
        val type = BrookTargetType.entries.find { it.code == code } ?: return null
        val hLen = buf.get().toInt() and 0xFF
        if (buf.remaining() < hLen + 2) return null
        val hBytes = ByteArray(hLen)
        buf.get(hBytes)
        val port = buf.short.toInt() and 0xFFFF
        return BrookRequest(type, String(hBytes, StandardCharsets.UTF_8), port)
    }
}
