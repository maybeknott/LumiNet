package com.luminet.android.tunnel

class OnDeviceDpiEvader(val defaultSplitOffset: Int = 2) {
    var evadedCount: Long = 0
        private set

    fun applySniSplit(clientHello: ByteArray, splitOffset: Int): List<ByteArray> {
        evadedCount++
        if (clientHello.size < 5 || clientHello[0] != 0x16.toByte()) {
            return listOf(clientHello)
        }
        val pos = splitOffset.coerceIn(1, clientHello.size - 1)
        return listOf(
            clientHello.copyOfRange(0, pos),
            clientHello.copyOfRange(pos, clientHello.size)
        )
    }

    fun applyHttpDesync(request: ByteArray): ByteArray {
        evadedCount++
        val str = try { String(request, Charsets.UTF_8) } catch (e: Exception) { return request }
        val lines = str.lines()
        val modified = lines.joinToString("\r\n") { line ->
            if (line.lowercase().startsWith("host:")) {
                val parts = line.split(":", limit = 2)
                if (parts.size == 2) "hOst: ${parts[1].trim()}" else line
            } else {
                line
            }
        }
        return modified.toByteArray(Charsets.UTF_8)
    }

    fun generateOutOfOrderChunks(data: ByteArray, chunkSize: Int): List<ByteArray> {
        evadedCount++
        val size = maxOf(1, chunkSize)
        val chunks = mutableListOf<ByteArray>()
        var offset = 0
        while (offset < data.size) {
            val end = minOf(offset + size, data.size)
            chunks.add(data.copyOfRange(offset, end))
            offset = end
        }

        if (chunks.size > 1) {
            val tmp = chunks[0]
            chunks[0] = chunks[1]
            chunks[1] = tmp
        }
        return chunks
    }

    fun craftTtlDecoyPair(realPayload: ByteArray, decoyTtl: Byte): Pair<Pair<Byte, ByteArray>, Pair<Byte, ByteArray>> {
        evadedCount++
        val decoy = realPayload.clone()
        for (i in decoy.indices) {
            decoy[i] = (decoy[i].toInt() xor 0x55).toByte()
        }
        return Pair(Pair(decoyTtl, decoy), Pair(64.toByte(), realPayload))
    }
}
