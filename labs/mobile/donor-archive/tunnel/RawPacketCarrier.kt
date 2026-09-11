package com.luminet.android.tunnel

data class RawCarrierPacket(
    val sequence: Int,
    val sessionId: Int,
    val checksum: Short,
    val payload: ByteArray
)

class RawPacketCarrier {
    val magic: Int = 0x50514554 // "PQET"

    fun computeChecksum(data: ByteArray): Short {
        var sum = 0
        var i = 0
        while (i < data.size - 1) {
            val word = ((data[i].toInt() and 0xFF) shl 8) or (data[i + 1].toInt() and 0xFF)
            sum += word
            i += 2
        }
        if (data.size % 2 == 1) {
            sum += (data[data.size - 1].toInt() and 0xFF) shl 8
        }
        while (sum > 0xFFFF) {
            sum = (sum and 0xFFFF) + (sum ushr 16)
        }
        return (sum.inv() and 0xFFFF).toShort()
    }

    fun encode(seq: Int, session: Int, payload: ByteArray): ByteArray {
        val csum = computeChecksum(payload)
        val out = ByteArray(4 + 4 + 4 + 2 + 2 + payload.size)
        // Magic
        out[0] = (magic ushr 24).toByte()
        out[1] = (magic ushr 16).toByte()
        out[2] = (magic ushr 8).toByte()
        out[3] = magic.toByte()
        // Sequence
        out[4] = (seq ushr 24).toByte()
        out[5] = (seq ushr 16).toByte()
        out[6] = (seq ushr 8).toByte()
        out[7] = seq.toByte()
        // Session ID
        out[8] = (session ushr 24).toByte()
        out[9] = (session ushr 16).toByte()
        out[10] = (session ushr 8).toByte()
        out[11] = session.toByte()
        // Checksum
        out[12] = (csum.toInt() ushr 8).toByte()
        out[13] = csum.toByte()
        // Length
        val len = payload.size
        out[14] = (len ushr 8).toByte()
        out[15] = len.toByte()
        System.arraycopy(payload, 0, out, 16, len)
        return out
    }
}
