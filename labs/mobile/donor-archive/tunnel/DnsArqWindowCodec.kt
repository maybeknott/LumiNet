package com.luminet.android.tunnel

data class DnsArqChunk(
    val seq: Int,
    val isLast: Boolean,
    val data: ByteArray
)

class DnsArqWindowCodec(val rootDomain: String) {
    private val buffer = mutableMapOf<Int, ByteArray>()

    fun formatQuery(seq: Int, isLast: Boolean, hexPayload: String): String {
        val flag = if (isLast) "1" else "0"
        return "arq-${seq}-${flag}-${hexPayload}.$rootDomain"
    }

    fun parseQuery(query: String): DnsArqChunk? {
        if (!query.endsWith(".$rootDomain")) return null
        val label = query.removeSuffix(".$rootDomain")
        val parts = label.split("-")
        if (parts.size != 4 || parts[0] != "arq") return null
        val seq = parts[1].toIntOrNull() ?: return null
        val isLast = parts[2] == "1"
        val payload = parts[3].toByteArray(Charsets.UTF_8)
        return DnsArqChunk(seq, isLast, payload)
    }

    fun insert(chunk: DnsArqChunk) {
        buffer[chunk.seq] = chunk.data
    }

    fun isComplete(maxSeq: Int): Boolean {
        for (i in 0..maxSeq) {
            if (!buffer.containsKey(i)) return false
        }
        return true
    }
}
