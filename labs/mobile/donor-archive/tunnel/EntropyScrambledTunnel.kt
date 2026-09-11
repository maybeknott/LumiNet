package com.luminet.android.tunnel

import java.nio.ByteBuffer
import java.security.SecureRandom
import kotlin.math.ln
import kotlin.math.max

class EntropyScrambledTunnel(
    private val secretKey: ByteArray,
    minPad: Int = 8,
    maxPad: Int = 32
) {
    private val minPadding = max(4, minPad)
    private val maxPadding = max(minPadding + 8, maxPad)
    private val random = SecureRandom()

    fun scramblePacket(payload: ByteArray, seed: Long): ByteArray {
        val padRange = maxPadding - minPadding
        val padLen = minPadding + (random.nextInt(padRange))

        val totalLen = 4 + payload.size + padLen
        val buf = ByteBuffer.allocate(totalLen)
        buf.putShort(payload.size.toShort())
        buf.putShort(padLen.toShort())
        buf.put(payload)

        val pad = ByteArray(padLen)
        random.nextBytes(pad)
        buf.put(pad)

        val raw = buf.array()
        applyMask(raw, seed)
        return raw
    }

    fun descramblePacket(scrambled: ByteArray, seed: Long): ByteArray? {
        if (scrambled.size < 4) return null
        val unmasked = scrambled.clone()
        applyMask(unmasked, seed)

        val buf = ByteBuffer.wrap(unmasked)
        val pLen = buf.getShort().toInt() and 0xFFFF
        val padLen = buf.getShort().toInt() and 0xFFFF

        if (unmasked.size < 4 + pLen + padLen) return null
        val payload = ByteArray(pLen)
        buf.get(payload)
        return payload
    }

    private fun applyMask(data: ByteArray, seed: Long) {
        var s = seed
        for (i in data.indices) {
            // Pseudo-random LCG stream from seed and secret key
            s = (s * 6364136223846793005L + 1442695040888963407L)
            val streamByte = ((s shr 33) xor secretKey[i % secretKey.size].toLong()).toByte()
            data[i] = (data[i].toInt() xor streamByte.toInt()).toByte()
        }
    }

    companion object {
        fun calculateShannonEntropy(data: ByteArray): Double {
            if (data.isEmpty()) return 0.0
            val counts = IntArray(256)
            for (b in data) {
                counts[b.toInt() and 0xFF]++
            }
            val total = data.size.toDouble()
            var entropy = 0.0
            val log2 = ln(2.0)
            for (c in counts) {
                if (c > 0) {
                    val p = c / total
                    entropy -= p * (ln(p) / log2)
                }
            }
            return entropy
        }
    }
}
