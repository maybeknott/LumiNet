package com.luminet.android.tunnel

import java.util.TreeMap

data class RangeChunk(
    val index: Int,
    val start: Long,
    val end: Long,
    val total: Long
) {
    fun length(): Long = end - start + 1
    fun toRangeHeader(): String = "bytes=-"
}

object RangeChunkCalculator {
    const val DEFAULT_CHUNK_SIZE: Long = 262144L // 256 KiB
    const val MAX_STREAM_BYTES: Long = 17179869184L // 16 GiB

    fun computeChunks(totalBytes: Long, chunkSize: Long = DEFAULT_CHUNK_SIZE): List<RangeChunk> {
        require(totalBytes > 0) { "Total bytes must be positive" }
        require(totalBytes <= MAX_STREAM_BYTES) { "Total bytes exceeds maximum stream limit" }

        val sz = if (chunkSize <= 0) DEFAULT_CHUNK_SIZE else chunkSize
        val chunks = mutableListOf<RangeChunk>()
        var start = 0L
        var idx = 0

        while (start < totalBytes) {
            val end = (start + sz - 1).coerceAtMost(totalBytes - 1)
            chunks.add(RangeChunk(idx, start, end, totalBytes))
            start = end + 1
            idx++
        }

        return chunks
    }

    fun parseContentRange(headerVal: String): Triple<Long, Long, Long>? {
        val clean = headerVal.trim()
        if (!clean.lowercase().startsWith("bytes ")) return null

        val rest = clean.substring("bytes ".length).trim()
        val parts = rest.split("/")
        if (parts.size != 2) return null

        val total = parts[1].trim().toLongOrNull() ?: return null
        val bounds = parts[0].trim().split("-")
        if (bounds.size != 2) return null

        val start = bounds[0].trim().toLongOrNull() ?: return null
        val end = bounds[1].trim().toLongOrNull() ?: return null

        return if (start in 0..end && end < total) {
            Triple(start, end, total)
        } else {
            null
        }
    }
}

class RangeParallelStitcher(val totalBytes: Long) {
    private val chunks = TreeMap<Long, ByteArray>()
    private var nextExpectedStart = 0L

    fun ingest(start: Long, data: ByteArray) {
        require(start + data.size <= totalBytes) { "Chunk range exceeds total expected bytes" }
        if (!chunks.containsKey(start)) {
            chunks[start] = data.copyOf()
        }
    }

    fun drainContiguous(): ByteArray {
        val out = mutableListOf<Byte>()
        while (chunks.containsKey(nextExpectedStart)) {
            val data = chunks.remove(nextExpectedStart)!!
            for (b in data) {
                out.add(b)
            }
            nextExpectedStart += data.size
        }
        return out.toByteArray()
    }

    fun isComplete(): Boolean = nextExpectedStart == totalBytes
}
