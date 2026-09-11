// Copyright 2024-2026 LumiNet Authors. All Rights Reserved.
package com.luminet.android.tunnel

import java.nio.ByteBuffer
import java.nio.charset.StandardCharsets
import javax.crypto.Mac
import javax.crypto.spec.SecretKeySpec

data class IdentityTunnelHeader(
    val version: Byte = 1,
    val targetPort: Int,
    val authToken: ByteArray,
    val targetDomain: String
)

object IdentityTunnelCodec {
    val MAGIC = byteArrayOf('P'.code.toByte(), 'A'.code.toByte(), 'N'.code.toByte(), 'G'.code.toByte())

    fun encode(targetPort: Int, token: ByteArray, domain: String): ByteArray {
        val domainBytes = domain.toByteArray(StandardCharsets.UTF_8)
        val buf = ByteBuffer.allocate(4 + 1 + 2 + 32 + 1 + domainBytes.size)
        buf.put(MAGIC)
        buf.put(1.toByte()) // version
        buf.putShort(targetPort.toShort())
        buf.put(token, 0, 32)
        buf.put(domainBytes.size.toByte())
        buf.put(domainBytes)
        return buf.array()
    }

    fun decode(data: ByteArray): IdentityTunnelHeader? {
        if (data.size < 40) return null
        val buf = ByteBuffer.wrap(data)
        val magic = ByteArray(4)
        buf.get(magic)
        if (!magic.contentEquals(MAGIC)) return null
        val ver = buf.get()
        if (ver != 1.toByte()) return null
        val port = buf.short.toInt() and 0xFFFF
        val token = ByteArray(32)
        buf.get(token)
        val dLen = buf.get().toInt() and 0xFF
        if (buf.remaining() < dLen) return null
        val dBytes = ByteArray(dLen)
        buf.get(dBytes)
        return IdentityTunnelHeader(ver, port, token, String(dBytes, StandardCharsets.UTF_8))
    }

    fun verifyToken(token: ByteArray, secret: ByteArray, subject: String): Boolean {
        val mac = Mac.getInstance("HmacSHA256")
        mac.init(SecretKeySpec(secret, "HmacSHA256"))
        val expected = mac.doFinal(subject.toByteArray(StandardCharsets.UTF_8))
        return expected.contentEquals(token)
    }
}
