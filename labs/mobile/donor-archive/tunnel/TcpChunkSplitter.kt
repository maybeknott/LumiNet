// Copyright 2024-2026 LumiNet Authors. All Rights Reserved.
package com.luminet.android.tunnel

object TcpChunkSplitter {
    fun splitBytes(data: ByteArray, chunkSize: Int): List<ByteArray> {
        if (chunkSize <= 0 || data.isEmpty()) return listOf(data)
        val result = mutableListOf<ByteArray>()
        var offset = 0
        while (offset < data.size) {
            val end = (offset + chunkSize).coerceAtMost(data.size)
            result.add(data.copyOfRange(offset, end))
            offset += chunkSize
        }
        return result
    }

    fun mutateHeaderCase(headerLine: String): String {
        val parts = headerLine.split(":", limit = 2)
        if (parts.size != 2) return headerLine
        val key = parts[0]
        val sb = StringBuilder()
        for (i in key.indices) {
            val ch = key[i]
            sb.append(if (i % 2 == 0) ch.lowercaseChar() else ch.uppercaseChar())
        }
        sb.append(":")
        sb.append(parts[1])
        return sb.toString()
    }
}
