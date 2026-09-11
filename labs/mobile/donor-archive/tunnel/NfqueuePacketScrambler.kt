package com.luminet.android.tunnel

import java.util.concurrent.ConcurrentHashMap

enum class AndroidScrambleAction {
    ACCEPT,
    ALTER_TTL,
    MARK_PACKET
}

data class AndroidShortcut(
    val createdAt: Long = System.currentTimeMillis(),
    val ttlMs: Long,
    var packetCount: Long = 0
)

class NfqueuePacketScrambler(
    val queueNum: Int,
    val defaultMark: Long
) {
    var ttlHopLimit: Int = 64
    private val shortcuts = ConcurrentHashMap<String, AndroidShortcut>()
    var totalScrambled: Long = 0L
        private set

    fun addShortcut(dest: String, ttlMs: Long) {
        shortcuts[dest] = AndroidShortcut(ttlMs = ttlMs)
    }

    fun hasActiveShortcut(dest: String): Boolean {
        val entry = shortcuts[dest] ?: return false
        if (System.currentTimeMillis() - entry.createdAt < entry.ttlMs) {
            entry.packetCount++
            return true
        }
        return false
    }

    fun processIpPacket(dest: String, packet: ByteArray): AndroidScrambleAction {
        if (hasActiveShortcut(dest)) {
            return AndroidScrambleAction.MARK_PACKET
        }

        totalScrambled++
        if (packet.size < 40) return AndroidScrambleAction.ACCEPT

        // IPv4 check
        if ((packet[0].toInt() shr 4) and 0x0F == 4) {
            val proto = packet[9].toInt() and 0xFF
            if (proto == 6) { // TCP
                val ihl = (packet[0].toInt() and 0x0F) * 4
                if (ihl + 13 < packet.size) {
                    val flags = packet[ihl + 13].toInt() and 0xFF
                    // SYN+ACK check (0x12)
                    if ((flags and 0x12) == 0x12) {
                        packet[8] = ttlHopLimit.toByte()
                        return AndroidScrambleAction.ALTER_TTL
                    }
                }
            }
        }
        return AndroidScrambleAction.ACCEPT
    }
}
