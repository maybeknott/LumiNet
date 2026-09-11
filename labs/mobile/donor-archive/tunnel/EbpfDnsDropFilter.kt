package com.luminet.android.tunnel

class EbpfDnsDropFilter {
    var droppedCount = 0
    var passedCount = 0

    fun inspectPacket(ipId: Int, fragOff: Int, srcPort: Int, dnsPayload: ByteArray): Boolean {
        if (srcPort != 53) {
            passedCount++
            return true
        }
        if (ipId == 0) {
            droppedCount++
            return false
        }
        if (fragOff == 0x0040) {
            droppedCount++
            return false
        }
        if (dnsPayload.size < 12) {
            passedCount++
            return true
        }

        val answerRRs = ((dnsPayload[6].toInt() and 0xFF) shl 8) or (dnsPayload[7].toInt() and 0xFF)
        val authRRs = ((dnsPayload[8].toInt() and 0xFF) shl 8) or (dnsPayload[9].toInt() and 0xFF)
        val aaBit = (dnsPayload[2].toInt() and 0x04) != 0

        if (answerRRs == 1 && authRRs == 0 && aaBit) {
            droppedCount++
            return false
        }

        passedCount++
        return true
    }
}
