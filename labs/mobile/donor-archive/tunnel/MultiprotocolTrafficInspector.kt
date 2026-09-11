package com.luminet.android.tunnel

import java.nio.ByteBuffer

enum class AndroidInspectedProto {
    UNKNOWN,
    RDP,
    SSH,
    TLS,
    HTTP,
    WEBSOCKET
}

enum class AndroidVerdict {
    PERMITTED,
    DENIED,
    NEEDS_MORE_DATA
}

data class AndroidInspectorPolicy(
    val allowRdp: Boolean = true,
    val allowSsh: Boolean = true,
    val allowTls: Boolean = true,
    val allowHttp: Boolean = true,
    val enforceSni: Boolean = false
)

class MultiprotocolTrafficInspector(val policy: AndroidInspectorPolicy = AndroidInspectorPolicy()) {
    var inspectedCount: Long = 0
        private set

    fun inspectStream(data: ByteArray): Triple<AndroidInspectedProto, AndroidVerdict, String?> {
        inspectedCount++
        if (data.isEmpty()) return Triple(AndroidInspectedProto.UNKNOWN, AndroidVerdict.NEEDS_MORE_DATA, null)

        val str = try { String(data, Charsets.UTF_8) } catch (e: Exception) { "" }

        // SSH Check
        if (str.startsWith("SSH-")) {
            val banner = str.lines().firstOrNull() ?: ""
            val verdict = if (policy.allowSsh) AndroidVerdict.PERMITTED else AndroidVerdict.DENIED
            return Triple(AndroidInspectedProto.SSH, verdict, banner)
        }

        // TLS Handshake Check
        if (data.size >= 5 && data[0] == 0x16.toByte() && data[1] == 0x03.toByte()) {
            val sni = extractSni(data)
            if (policy.enforceSni && sni == null) {
                return Triple(AndroidInspectedProto.TLS, AndroidVerdict.DENIED, null)
            }
            val verdict = if (policy.allowTls) AndroidVerdict.PERMITTED else AndroidVerdict.DENIED
            return Triple(AndroidInspectedProto.TLS, verdict, sni)
        }

        // RDP Check (TPKT header: 0x03 0x00 ...)
        if (data.size >= 4 && data[0] == 0x03.toByte() && data[1] == 0x00.toByte()) {
            val verdict = if (policy.allowRdp) AndroidVerdict.PERMITTED else AndroidVerdict.DENIED
            return Triple(AndroidInspectedProto.RDP, verdict, "TPKT")
        }

        // HTTP / WebSocket
        if (str.startsWith("GET ") || str.startsWith("POST ") || str.startsWith("CONNECT ")) {
            val isWs = str.lowercase().contains("upgrade: websocket")
            val proto = if (isWs) AndroidInspectedProto.WEBSOCKET else AndroidInspectedProto.HTTP
            val verdict = if (policy.allowHttp) AndroidVerdict.PERMITTED else AndroidVerdict.DENIED
            return Triple(proto, verdict, null)
        }

        if (data.size < 8) return Triple(AndroidInspectedProto.UNKNOWN, AndroidVerdict.NEEDS_MORE_DATA, null)
        return Triple(AndroidInspectedProto.UNKNOWN, AndroidVerdict.DENIED, null)
    }

    private fun extractSni(data: ByteArray): String? {
        if (data.size < 43 || data[5] != 0x01.toByte()) return null
        var cursor = 43
        if (cursor >= data.size) return null

        val sessLen = data[cursor].toInt() and 0xFF
        cursor += 1 + sessLen
        if (cursor + 2 > data.size) return null

        val cipherLen = ByteBuffer.wrap(data, cursor, 2).short.toInt() and 0xFFFF
        cursor += 2 + cipherLen
        if (cursor + 1 > data.size) return null

        val compLen = data[cursor].toInt() and 0xFF
        cursor += 1 + compLen
        if (cursor + 2 > data.size) return null

        val extLen = ByteBuffer.wrap(data, cursor, 2).short.toInt() and 0xFFFF
        cursor += 2
        val extEnd = minOf(cursor + extLen, data.size)

        while (cursor + 4 <= extEnd) {
            val extType = ByteBuffer.wrap(data, cursor, 2).short.toInt() and 0xFFFF
            val extDataLen = ByteBuffer.wrap(data, cursor + 2, 2).short.toInt() and 0xFFFF
            cursor += 4

            if (extType == 0x0000 && cursor + 5 <= extEnd) { // SNI
                val nameType = data[cursor + 2]
                val nameLen = ByteBuffer.wrap(data, cursor + 3, 2).short.toInt() and 0xFFFF
                if (nameType == 0.toByte() && cursor + 5 + nameLen <= extEnd) {
                    return String(data, cursor + 5, nameLen, Charsets.UTF_8)
                }
            }
            cursor += extDataLen
        }
        return null
    }
}
