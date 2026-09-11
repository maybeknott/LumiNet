// Copyright 2024-2026 LumiNet Authors. All Rights Reserved.
package com.luminet.android.tunnel

import java.nio.ByteBuffer

data class SwitchPacketFrame(
    val source: ByteArray,      // 5 bytes (40-bit)
    val destination: ByteArray, // 5 bytes
    val etherType: Int,         // 2 bytes
    val payload: ByteArray
) {
    fun encode(): ByteArray {
        val buf = ByteBuffer.allocate(10 + 2 + payload.size)
        buf.put(source, 0, 5)
        buf.put(destination, 0, 5)
        buf.putShort(etherType.toShort())
        buf.put(payload)
        return buf.array()
    }

    companion object {
        fun decode(data: ByteArray): SwitchPacketFrame? {
            if (data.size < 12) return null
            val buf = ByteBuffer.wrap(data)
            val src = ByteArray(5)
            val dst = ByteArray(5)
            buf.get(src)
            buf.get(dst)
            val eth = buf.short.toInt() and 0xFFFF
            val payload = ByteArray(buf.remaining())
            buf.get(payload)
            return SwitchPacketFrame(src, dst, eth, payload)
        }
    }
}

class VirtualEthernetSwitch(private val agingDurationMs: Long = 60_000) {
    private val fdb = mutableMapOf<String, Pair<String, Long>>()
    private val lock = Any()

    fun learn(nodeIdHex: String, endpoint: String, nowMs: Long = System.currentTimeMillis()) = synchronized(lock) {
        fdb[nodeIdHex] = Pair(endpoint, nowMs)
    }

    fun lookup(nodeIdHex: String, nowMs: Long = System.currentTimeMillis()): String? = synchronized(lock) {
        val entry = fdb[nodeIdHex] ?: return null
        if (nowMs - entry.second > agingDurationMs) {
            fdb.remove(nodeIdHex)
            return null
        }
        entry.first
    }
}
