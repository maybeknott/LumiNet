package com.luminet.android.tunnel

class OverTlsStreamCodec(val maxPadding: Int = 32) {
    companion object {
        const val MAGIC: Short = 0x544F
    }

    fun encode(payload: ByteArray, paddingLen: Int): ByteArray {
        val pLen = paddingLen.coerceAtMost(maxPadding)
        val total = 6 + payload.size + pLen
        val buf = ByteArray(total)

        // Magic 0x544F
        buf[0] = 0x54
        buf[1] = 0x4F
        // Type Data (0x01)
        buf[2] = 0x01
        // Padding len
        buf[3] = pLen.toByte()
        // Payload len (big endian)
        buf[4] = ((payload.size ushr 8) and 0xFF).toByte()
        buf[5] = (payload.size and 0xFF).toByte()

        System.arraycopy(payload, 0, buf, 6, payload.size)
        for (i in 0 until pLen) {
            buf[6 + payload.size + i] = ((i * 37) xor 0xA5).toByte()
        }
        return buf
    }

    fun decode(buf: ByteArray): ByteArray? {
        if (buf.size < 6) return null
        if (buf[0] != 0x54.toByte() || buf[1] != 0x4F.toByte()) return null

        val pLen = buf[3].toInt() and 0xFF
        val nLen = ((buf[4].toInt() and 0xFF) shl 8) or (buf[5].toInt() and 0xFF)
        if (buf.size < 6 + nLen + pLen) return null

        val out = ByteArray(nLen)
        System.arraycopy(buf, 6, out, 0, nLen)
        return out
    }
}
