package com.luminet.android.tunnel

class DpiPatternMasker(
    val splitOffset: Int = 5,
    val insertNoiseRecord: Boolean = true
) {
    companion object {
        val FAKE_ALERT_HEADER = byteArrayOf(0x15, 0x03, 0x03, 0x00, 0x02, 0x01, 0x00)
    }

    fun fragmentPayload(payload: ByteArray): List<ByteArray> {
        if (payload.size <= splitOffset) return listOf(payload)
        val frags = mutableListOf<ByteArray>()

        if (insertNoiseRecord && payload.size >= 2 && payload[0] == 0x16.toByte() && payload[1] == 0x03.toByte()) {
            frags.add(FAKE_ALERT_HEADER.copyOf())
        }

        val splitAt = splitOffset.coerceAtMost(payload.size - 1)
        frags.add(payload.copyOfRange(0, splitAt))
        frags.add(payload.copyOfRange(splitAt, payload.size))
        return frags
    }

    fun reassemblePayload(fragments: List<ByteArray>): ByteArray {
        val list = mutableListOf<Byte>()
        for (f in fragments) {
            if (f.contentEquals(FAKE_ALERT_HEADER)) continue
            for (b in f) list.add(b)
        }
        return list.toByteArray()
    }
}
