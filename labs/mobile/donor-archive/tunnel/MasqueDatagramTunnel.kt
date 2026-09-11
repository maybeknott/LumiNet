package com.luminet.android.tunnel

import java.nio.ByteBuffer

class MasqueDatagramTunnel(val contextId: Long = 0) {

    fun encodeDatagram(payload: ByteArray): ByteArray {
        val varintBytes = encodeVarint(contextId)
        val buf = ByteBuffer.allocate(varintBytes.size + payload.size)
        buf.put(varintBytes)
        buf.put(payload)
        return buf.array()
    }

    fun decodeDatagram(data: ByteArray): Pair<Long, ByteArray>? {
        if (data.isEmpty()) return null
        val (ctxId, varintLen) = decodeVarint(data) ?: return null
        val payload = data.copyOfRange(varintLen, data.size)
        return Pair(ctxId, payload)
    }

    private fun encodeVarint(value: Long): ByteArray {
        return if (value < 64) {
            byteArrayOf(value.toByte())
        } else if (value < 16384) {
            val v = (0x4000 or (value.toInt() and 0x3FFF))
            byteArrayOf((v shr 8).toByte(), (v and 0xFF).toByte())
        } else {
            val v = (0x80000000L or (value and 0x3FFFFFFFL))
            ByteBuffer.allocate(4).putInt(v.toInt()).array()
        }
    }

    private fun decodeVarint(data: ByteArray): Pair<Long, Int>? {
        if (data.isEmpty()) return null
        val first = data[0].toInt() and 0xFF
        val prefix = first shr 6
        return when (prefix) {
            0 -> Pair((first and 0x3F).toLong(), 1)
            1 -> {
                if (data.size < 2) null
                else {
                    val v = ((first and 0x3F) shl 8) or (data[1].toInt() and 0xFF)
                    Pair(v.toLong(), 2)
                }
            }
            2 -> {
                if (data.size < 4) null
                else {
                    val buf = ByteBuffer.wrap(data)
                    val v = buf.getInt().toLong() and 0x3FFFFFFFL
                    Pair(v, 4)
                }
            }
            else -> null
        }
    }
}
