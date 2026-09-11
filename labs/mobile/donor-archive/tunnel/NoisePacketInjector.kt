// Copyright 2024-2026 LumiNet Authors. All Rights Reserved.
package com.luminet.android.tunnel

import java.nio.ByteBuffer

class NoisePacketInjector(
    private val minPadding: Int = 8,
    private val maxPadding: Int = 64
) {
    private val magic = byteArrayOf(0x17.toByte(), 0x03.toByte(), 0x03.toByte())

    fun synthesizeNoiseFrame(seed: Long): ByteArray {
        val span = (maxPadding - minPadding).coerceAtLeast(1)
        val padLen = minPadding + (seed % span).toInt()
        val buf = ByteBuffer.allocate(3 + 2 + padLen)
        buf.put(magic)
        buf.putShort(padLen.toShort())

        var cur = seed
        for (i in 0 until padLen) {
            cur = cur * 6364136223846793005L + 1L
            buf.put((cur ushr 32).toByte())
        }
        return buf.array()
    }
}
