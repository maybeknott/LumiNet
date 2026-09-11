package com.luminet.android.tunnel

import java.util.ArrayDeque
import java.util.concurrent.ConcurrentHashMap
import java.util.concurrent.atomic.AtomicInteger

/**
 * High-Density Lowercase Base36 Codec for DNS Tunneling.
 * Encodes 7-byte blocks into 11-character base36 characters [0-9a-z].
 * Conforms to §8 structural cleanroom rules.
 */
object LowerBase36 {
    private const val ALPHABET = "0123456789abcdefghijklmnopqrstuvwxyz"
    private val ENCODED_CHARS_BY_BYTES = intArrayOf(0, 2, 4, 5, 7, 8, 10, 11)
    private val DECODED_BYTES_BY_CHARS = intArrayOf(0, 0, 1, 0, 2, 3, 0, 4, 5, 0, 6, 7)

    fun encodedLen(n: Int): Int {
        if (n <= 0) return 0
        val blocks = n / 7
        val rem = n % 7
        return blocks * 11 + ENCODED_CHARS_BY_BYTES[rem]
    }

    fun encode(data: ByteArray): String {
        if (data.isEmpty()) return ""
        val outLen = encodedLen(data.size)
        val out = CharArray(outLen)
        var offset = 0
        var srcIdx = 0

        while (data.size - srcIdx >= 7) {
            var v = 0L
            for (i in 0 until 7) {
                v = (v shl 8) or (data[srcIdx + i].toLong() and 0xFF)
            }
            writeBase36Block(out, offset, v, 11)
            offset += 11
            srcIdx += 7
        }

        val rem = data.size - srcIdx
        if (rem > 0) {
            var v = 0L
            for (i in 0 until rem) {
                v = (v shl 8) or (data[srcIdx + i].toLong() and 0xFF)
            }
            val charCount = ENCODED_CHARS_BY_BYTES[rem]
            writeBase36Block(out, offset, v, charCount)
        }

        return String(out)
    }

    private fun writeBase36Block(dst: CharArray, offset: Int, value: Long, count: Int) {
        var v = value
        for (i in count - 1 downTo 0) {
            dst[offset + i] = ALPHABET[(v % 36).toInt()]
            v /= 36
        }
    }

    fun decode(input: String): ByteArray {
        if (input.isEmpty()) return ByteArray(0)
        val s = input.lowercase()

        val fullBlocks = s.length / 11
        val remChars = s.length % 11
        val totalBytes = fullBlocks * 7 + if (remChars in 0..11) DECODED_BYTES_BY_CHARS[remChars] else 0
        val out = ByteArray(totalBytes)
        var outIdx = 0
        var offset = 0

        for (b in 0 until fullBlocks) {
            val v = parseBlock(s.substring(offset, offset + 11))
            for (shift in 6 downTo 0) {
                out[outIdx++] = ((v shr (shift * 8)) and 0xFF).toByte()
            }
            offset += 11
        }

        if (remChars > 0) {
            val v = parseBlock(s.substring(offset, offset + remChars))
            val expBytes = DECODED_BYTES_BY_CHARS[remChars]
            for (shift in (expBytes - 1) downTo 0) {
                out[outIdx++] = ((v shr (shift * 8)) and 0xFF).toByte()
            }
        }

        return out
    }

    private fun parseBlock(block: String): Long {
        var v = 0L
        for (ch in block) {
            val digit = when (ch) {
                in '0'..'9' -> ch - '0'
                in 'a'..'z' -> ch - 'a' + 10
                else -> throw IllegalArgumentException("invalid lower base36 character: $ch")
            }
            v = v * 36 + digit
        }
        return v
    }
}

/**
 * 6-level Multi-Level Priority Queue with O(1) scheduling.
 */
class MultiLevelQueue<T : Any>(initialCapacity: Int = 16) {
    companion object {
        const val NUM_PRIORITIES = 6
        const val DEFAULT_PRIORITY = 3
    }

    private data class QueueEntry<T>(val key: Long, val item: T)
    private data class CensusEntry(val priority: Int, val entry: QueueEntry<*>)

    private val queues = Array(NUM_PRIORITIES) { ArrayDeque<QueueEntry<T>>() }
    private val census = HashMap<Long, CensusEntry>(initialCapacity)
    private var bitmask = 0
    private val fastSize = AtomicInteger(0)

    @Synchronized
    fun push(priority: Int, key: Long, item: T): Boolean {
        if (census.containsKey(key)) return false
        val p = if (priority in 0 until NUM_PRIORITIES) priority else DEFAULT_PRIORITY

        val qEntry = QueueEntry(key, item)
        queues[p].addLast(qEntry)
        census[key] = CensusEntry(p, qEntry)
        bitmask = bitmask or (1 shl p)
        fastSize.incrementAndGet()
        return true
    }

    @Synchronized
    fun pop(): Pair<T, Int>? {
        while (bitmask != 0) {
            val p = Integer.numberOfTrailingZeros(bitmask)
            if (p >= NUM_PRIORITIES) {
                bitmask = 0
                return null
            }
            val q = queues[p]
            val entry = q.pollFirst()
            if (entry != null) {
                census.remove(entry.key)
                fastSize.decrementAndGet()
                if (q.isEmpty()) {
                    bitmask = bitmask and (1 shl p).inv()
                }
                return Pair(entry.item, p)
            } else {
                bitmask = bitmask and (1 shl p).inv()
            }
        }
        return null
    }

    @Synchronized
    fun removeByKey(key: Long): T? {
        val c = census.remove(key) ?: return null
        val q = queues[c.priority]
        val removed = q.firstOrNull { it.key == key }
        if (removed != null) {
            q.remove(removed)
            fastSize.decrementAndGet()
            if (q.isEmpty()) {
                bitmask = bitmask and (1 shl c.priority).inv()
            }
            return removed.item
        }
        return null
    }

    fun size(): Int = fastSize.get()
}

/**
 * Packed Control Block: 7 Bytes.
 * Type(1) + StreamID(2) + SeqNum(2) + FragID(1) + Total(1).
 */
data class PackedControlBlock(
    val packetType: Byte,
    val streamId: Short,
    val sequenceNum: Short,
    val fragmentId: Byte,
    val totalFragments: Byte,
) {
    companion object {
        const val BLOCK_SIZE = 7

        fun parseBlocks(payload: ByteArray): List<PackedControlBlock> {
            val blocks = mutableListOf<PackedControlBlock>()
            var offset = 0
            while (offset + BLOCK_SIZE <= payload.size) {
                val pType = payload[offset]
                val sId = (((payload[offset + 1].toInt() and 0xFF) shl 8) or (payload[offset + 2].toInt() and 0xFF)).toShort()
                val seq = (((payload[offset + 3].toInt() and 0xFF) shl 8) or (payload[offset + 4].toInt() and 0xFF)).toShort()
                val frag = payload[offset + 5]
                val total = payload[offset + 6]

                blocks.add(PackedControlBlock(pType, sId, seq, frag, total))
                offset += BLOCK_SIZE
            }
            return blocks
        }

        fun packBlocks(blocks: List<PackedControlBlock>): ByteArray {
            val dst = ByteArray(blocks.size * BLOCK_SIZE)
            var offset = 0
            for (b in blocks) {
                dst[offset] = b.packetType
                dst[offset + 1] = ((b.streamId.toInt() shr 8) and 0xFF).toByte()
                dst[offset + 2] = (b.streamId.toInt() and 0xFF).toByte()
                dst[offset + 3] = ((b.sequenceNum.toInt() shr 8) and 0xFF).toByte()
                dst[offset + 4] = (b.sequenceNum.toInt() and 0xFF).toByte()
                dst[offset + 5] = b.fragmentId
                dst[offset + 6] = b.totalFragments
                offset += BLOCK_SIZE
            }
            return dst
        }
    }
}
