// Copyright 2024-2026 LumiNet Authors. All Rights Reserved.
package com.luminet.android.tunnel

import java.nio.ByteBuffer

enum class ChannelOpcode(val code: Byte) {
    CHANNEL_OPEN(1),
    CHANNEL_DATA(2),
    CHANNEL_CLOSE(3),
    CHANNEL_ACK(4)
}

data class ChannelMuxFrame(
    val channelId: Int,
    val opcode: ChannelOpcode,
    val payload: ByteArray
) {
    fun encode(): ByteArray {
        val buf = ByteBuffer.allocate(7 + payload.size)
        buf.putInt(channelId)
        buf.put(opcode.code)
        buf.putShort(payload.size.toShort())
        buf.put(payload)
        return buf.array()
    }

    companion object {
        fun decode(data: ByteArray): ChannelMuxFrame? {
            if (data.size < 7) return null
            val buf = ByteBuffer.wrap(data)
            val cid = buf.int
            val opByte = buf.get()
            val op = ChannelOpcode.entries.find { it.code == opByte } ?: return null
            val len = buf.short.toInt() and 0xFFFF
            if (buf.remaining() < len) return null
            val payload = ByteArray(len)
            buf.get(payload)
            return ChannelMuxFrame(cid, op, payload)
        }
    }
}
