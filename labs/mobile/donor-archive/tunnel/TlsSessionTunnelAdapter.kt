package com.luminet.android.tunnel

import java.nio.ByteBuffer

data class AndroidSessionTicket(
    val ticketId: String,
    val serverName: String,
    val masterSecret: ByteArray,
    val maxEarlyData: Long,
    val expiresAtSecs: Long
)

class TlsSessionTunnelAdapter {
    private val ticketCache = mutableMapOf<String, AndroidSessionTicket>()

    fun storeTicket(ticket: AndroidSessionTicket) {
        ticketCache[ticket.serverName] = ticket
    }

    fun retrieveTicket(serverName: String, nowSecs: Long): AndroidSessionTicket? {
        val ticket = ticketCache[serverName] ?: return null
        if (nowSecs > ticket.expiresAtSecs) return null
        return ticket
    }

    fun frameEarlyData(ticketId: String, payload: ByteArray): ByteArray {
        val tBytes = ticketId.toByteArray()
        val buf = ByteBuffer.allocate(1 + tBytes.size + 2 + payload.size)
        buf.put(tBytes.size.toByte())
        buf.put(tBytes)
        buf.putShort(payload.size.toShort())
        buf.put(payload)
        return buf.array()
    }

    fun unframeEarlyData(data: ByteArray): Pair<String, ByteArray>? {
        if (data.size < 3) return null
        val tLen = data[0].toInt() and 0xFF
        if (data.size < 1 + tLen + 2) return null

        val ticketId = String(data.copyOfRange(1, 1 + tLen))
        val pLen = ((data[1 + tLen].toInt() and 0xFF) shl 8) or (data[2 + tLen].toInt() and 0xFF)
        val start = 3 + tLen
        if (data.size < start + pLen) return null

        val payload = data.copyOfRange(start, start + pLen)
        return Pair(ticketId, payload)
    }
}
