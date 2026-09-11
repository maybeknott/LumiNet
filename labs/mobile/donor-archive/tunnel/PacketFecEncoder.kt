package com.luminet.android.tunnel

class PacketFecEncoder(val groupSize: Int = 4) {
    fun computeParity(sources: List<ByteArray>): ByteArray {
        if (sources.isEmpty()) return ByteArray(0)
        val maxLen = sources.maxOf { it.size }
        val parity = ByteArray(maxLen)
        for (src in sources) {
            for (i in src.indices) {
                parity[i] = (parity[i].toInt() xor src[i].toInt()).toByte()
            }
        }
        return parity
    }

    fun recoverSingleMissing(knownSources: List<ByteArray>, parity: ByteArray, expectedLen: Int): ByteArray {
        val rec = parity.copyOf()
        for (src in knownSources) {
            for (i in src.indices) {
                if (i < rec.size) {
                    rec[i] = (rec[i].toInt() xor src[i].toInt()).toByte()
                }
            }
        }
        return rec.copyOf(expectedLen)
    }
}
