package com.luminet.android.tunnel

class EdnsSubnetScrubber(
    val maskIpv4Bits: Int = 24,
    val maskIpv6Bits: Int = 56,
    val stripCompletely: Boolean = false
) {
    fun maskIpv4(ip: String): String {
        val parts = ip.trim().split(".")
        if (parts.size != 4) return ip
        try {
            val octets = parts.map { it.toInt() }
            val raw = (octets[0] shl 24) or (octets[1] shl 16) or (octets[2] shl 8) or octets[3]
            val mask = if (maskIpv4Bits >= 32) -1 else if (maskIpv4Bits <= 0) 0 else -1 shl (32 - maskIpv4Bits)
            val masked = raw and mask
            val b0 = (masked ushr 24) and 0xFF
            val b1 = (masked ushr 16) and 0xFF
            val b2 = (masked ushr 8) and 0xFF
            val b3 = masked and 0xFF
            return "$b0.$b1.$b2.$b3"
        } catch (e: Exception) {
            return ip
        }
    }

    fun scrubPacket(packet: ByteArray): ByteArray {
        if (packet.size < 12) return packet
        val arcount = ((packet[10].toInt() and 0xFF) shl 8) or (packet[11].toInt() and 0xFF)
        if (arcount == 0) return packet
        return packet.copyOf()
    }
}
