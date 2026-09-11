package com.luminet.android.tunnel

import java.nio.ByteBuffer
import java.util.Random

enum class SniSegmentationStrategy {
    SNI_BORDER_SPLIT,
    MID_SNI_SPLIT,
    RANDOM_SPLIT
}

class SniSegmentationMasquerader(
    val strategy: SniSegmentationStrategy,
    val minChunkSize: Int = 8,
    val maxChunkSize: Int = 32
) {
    fun extractSni(data: ByteArray): Triple<String, Int, Int>? {
        if (data.size < 43 || data[0] != 0x16.toByte()) {
            return null
        }

        var idx = 43
        if (idx >= data.size) return null

        val sessionIdLen = data[idx].toInt() and 0xff
        idx += 1 + sessionIdLen
        if (idx + 2 >= data.size) return null

        val cipherLen = ByteBuffer.wrap(data, idx, 2).short.toInt() and 0xffff
        idx += 2 + cipherLen
        if (idx + 1 >= data.size) return null

        val compLen = data[idx].toInt() and 0xff
        idx += 1 + compLen
        if (idx + 2 >= data.size) return null

        val extLen = ByteBuffer.wrap(data, idx, 2).short.toInt() and 0xffff
        idx += 2
        val extEnd = (idx + extLen).coerceAtMost(data.size)

        while (idx + 4 <= extEnd) {
            val extType = ByteBuffer.wrap(data, idx, 2).short.toInt() and 0xffff
            val extSize = ByteBuffer.wrap(data, idx + 2, 2).short.toInt() and 0xffff
            idx += 4

            if (extType == 0 && idx + extSize <= extEnd && extSize >= 5) {
                val sniNameLen = ByteBuffer.wrap(data, idx + 3, 2).short.toInt() and 0xffff
                val sniStart = idx + 5
                val sniEnd = sniStart + sniNameLen
                if (sniEnd <= idx + extSize) {
                    val sni = String(data, sniStart, sniNameLen, Charsets.UTF_8)
                    return Triple(sni, sniStart, sniEnd)
                }
            }
            idx += extSize
        }

        return null
    }

    fun segmentStream(data: ByteArray, seed: Long): List<ByteArray> {
        if (data.isEmpty()) return emptyList()

        val sniInfo = extractSni(data)
        if (sniInfo != null) {
            val (_, start, end) = sniInfo
            when (strategy) {
                SniSegmentationStrategy.SNI_BORDER_SPLIT -> {
                    val chunks = ArrayList<ByteArray>()
                    if (start > 0) chunks.add(data.copyOfRange(0, start))
                    chunks.add(data.copyOfRange(start, end))
                    if (end < data.size) chunks.add(data.copyOfRange(end, data.size))
                    return chunks
                }
                SniSegmentationStrategy.MID_SNI_SPLIT -> {
                    val mid = start + (end - start) / 2
                    return listOf(data.copyOfRange(0, mid), data.copyOfRange(mid, data.size))
                }
                SniSegmentationStrategy.RANDOM_SPLIT -> {
                    // fallthrough
                }
            }
        }

        val rng = Random(seed)
        val chunks = ArrayList<ByteArray>()
        var curr = 0

        while (curr < data.size) {
            val rem = data.size - curr
            val step = if (rem <= minChunkSize) {
                rem
            } else {
                val span = (maxChunkSize - minChunkSize).coerceAtLeast(1)
                (minChunkSize + rng.nextInt(span)).coerceAtMost(rem)
            }
            chunks.add(data.copyOfRange(curr, curr + step))
            curr += step
        }

        return chunks
    }
}
