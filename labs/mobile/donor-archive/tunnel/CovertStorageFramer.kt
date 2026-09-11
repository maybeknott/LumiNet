package com.luminet.android.tunnel

import java.nio.ByteBuffer

data class CovertChunk(
    val streamId: Int,
    val sequence: Long,
    val isFin: Boolean,
    val payload: ByteArray
)

class CovertStorageFramer {
    companion object {
        val MAGIC = byteArrayOf(0x53, 0x4B, 0x52, 0x4B) // "SKRK"

        fun frameChunk(chunk: CovertChunk): ByteArray {
            val buf = ByteBuffer.allocate(22 + chunk.payload.size)
            buf.put(MAGIC)
            buf.putInt(chunk.streamId)
            buf.putLong(chunk.sequence)
            buf.put(if (chunk.isFin) 1.toByte() else 0.toByte())
            buf.putInt(chunk.payload.size)
            buf.put(computeCrc8(chunk.payload))
            buf.put(chunk.payload)
            return buf.array()
        }

        fun unframeChunk(buf: ByteArray): CovertChunk? {
            if (buf.size < 22) return null
            if (buf[0] != MAGIC[0] || buf[1] != MAGIC[1] || buf[2] != MAGIC[2] || buf[3] != MAGIC[3]) return null
            val bb = ByteBuffer.wrap(buf)
            bb.position(4)
            val streamId = bb.getInt()
            val sequence = bb.getLong()
            val isFin = bb.get() != 0.toByte()
            val payloadLen = bb.getInt()
            val expectedCrc = bb.get()
            if (buf.size < 22 + payloadLen) return null
            val payload = ByteArray(payloadLen)
            bb.get(payload)
            if (computeCrc8(payload) != expectedCrc) return null
            return CovertChunk(streamId, sequence, isFin, payload)
        }

        private fun computeCrc8(data: ByteArray): Byte {
            var crc = 0
            for (b in data) {
                crc = crc xor (b.toInt() and 0xFF)
                for (i in 0 until 8) {
                    crc = if ((crc and 0x80) != 0) (crc shl 1) xor 0x07 else crc shl 1
                }
            }
            return (crc and 0xFF).toByte()
        }
    }
}
