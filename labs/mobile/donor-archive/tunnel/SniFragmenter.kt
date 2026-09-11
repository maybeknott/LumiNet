package com.luminet.android.tunnel

import java.nio.ByteBuffer
import java.nio.charset.StandardCharsets

/**
 * Configuration parameters for 3-zone TLS ClientHello fragmentation.
 */
data class SniFragmentConfig(
    val beforeSniRange: Pair<Int, Int> = Pair(1, 5),
    val sniRange: Pair<Int, Int> = Pair(1, 3),
    val afterSniRange: Pair<Int, Int> = Pair(5, 20),
    val delayMsRange: Pair<Long, Long> = Pair(1L, 5L)
)

/**
 * Fragment slice representing an individual sub-packet payload and injected delay.
 */
data class FragmentSlice(
    val zone: String,
    val payload: ByteArray,
    val delayMs: Long
) {
    override fun equals(other: Any?): Boolean {
        if (this === other) return true
        if (javaClass != other?.javaClass) return false
        other as FragmentSlice
        return zone == other.zone && payload.contentEquals(other.payload) && delayMs == other.delayMs
    }

    override fun hashCode(): Int {
        var result = zone.hashCode()
        result = 31 * result + payload.contentHashCode()
        result = 31 * result + delayMs.hashCode()
        return result
    }
}

/**
 * Result plan for 3-zone packet fragmentation.
 */
data class SniFragmentPlan(
    val slices: List<FragmentSlice>,
    val totalBytes: Int,
    val detectedSni: String?
)

/**
 * 3-Zone TLS ClientHello SNI Fragmenter for DPI evasion.
 */
class SniFragmenter {

    /**
     * Extracts the Server Name Indication string from raw ClientHello packet bytes.
     */
    fun extractSni(packet: ByteArray): String? {
        return locateSni(packet)?.third
    }

    /**
     * Locates byte range (start, end, sni_name) inside ClientHello.
     */
    fun locateSni(packet: ByteArray): Triple<Int, Int, String>? {
        if (packet.size < 5 + 4 + 2 + 32 + 1) {
            return null
        }

        // Record type 0x16 = Handshake
        if (packet[0] != 0x16.toByte()) {
            return null
        }

        val recordLen = ((packet[3].toInt() and 0xFF) shl 8) or (packet[4].toInt() and 0xFF)
        if (packet.size < 5 + recordLen) {
            return null
        }

        var offset = 5
        // Handshake type 0x01 = ClientHello
        if (packet[offset] != 0x01.toByte()) {
            return null
        }

        val handshakeLen = ((packet[offset + 1].toInt() and 0xFF) shl 16) or
                ((packet[offset + 2].toInt() and 0xFF) shl 8) or
                (packet[offset + 3].toInt() and 0xFF)
        if (packet.size < offset + 4 + handshakeLen) {
            return null
        }
        offset += 4

        // Version (2) + Random (32)
        if (packet.size < offset + 2 + 32 + 1) {
            return null
        }
        offset += 2 + 32

        // Session ID
        val sessionIdLen = packet[offset].toInt() and 0xFF
        offset += 1
        if (packet.size < offset + sessionIdLen + 2) {
            return null
        }
        offset += sessionIdLen

        // Cipher Suites
        val cipherSuitesLen = ((packet[offset].toInt() and 0xFF) shl 8) or (packet[offset + 1].toInt() and 0xFF)
        offset += 2
        if (packet.size < offset + cipherSuitesLen + 1) {
            return null
        }
        offset += cipherSuitesLen

        // Compression Methods
        val compressionLen = packet[offset].toInt() and 0xFF
        offset += 1
        if (packet.size < offset + compressionLen + 2) {
            return null
        }
        offset += compressionLen

        // Extensions
        val extensionsLen = ((packet[offset].toInt() and 0xFF) shl 8) or (packet[offset + 1].toInt() and 0xFF)
        offset += 2
        val extensionsEnd = offset + extensionsLen
        if (packet.size < extensionsEnd) {
            return null
        }

        while (offset + 4 <= extensionsEnd) {
            val extType = ((packet[offset].toInt() and 0xFF) shl 8) or (packet[offset + 1].toInt() and 0xFF)
            val extLen = ((packet[offset + 2].toInt() and 0xFF) shl 8) or (packet[offset + 3].toInt() and 0xFF)
            offset += 4

            if (offset + extLen > extensionsEnd) {
                break
            }

            if (extType == 0x0000) { // Server Name Indication
                if (extLen < 5) return null
                val listLen = ((packet[offset].toInt() and 0xFF) shl 8) or (packet[offset + 1].toInt() and 0xFF)
                var listOff = offset + 2
                val listEnd = offset + 2 + listLen

                while (listOff + 3 <= listEnd) {
                    val nameType = packet[listOff]
                    val nameLen = ((packet[listOff + 1].toInt() and 0xFF) shl 8) or (packet[listOff + 2].toInt() and 0xFF)
                    listOff += 3

                    if (listOff + nameLen > listEnd) {
                        break
                    }

                    if (nameType == 0x00.toByte()) { // Hostname
                        val nameBytes = packet.copyOfRange(listOff, listOff + nameLen)
                        val nameStr = String(nameBytes, StandardCharsets.UTF_8)
                        return Triple(listOff, listOff + nameLen, nameStr)
                    }
                    listOff += nameLen
                }
            }
            offset += extLen
        }

        return null
    }

    /**
     * Splits packet into 3 zones and returns a fragmentation plan.
     */
    fun planFragments(packet: ByteArray, config: SniFragmentConfig = SniFragmentConfig()): SniFragmentPlan {
        val sniLoc = locateSni(packet)
        if (sniLoc == null || sniLoc.second <= sniLoc.first) {
            return SniFragmentPlan(
                slices = listOf(FragmentSlice("passthrough", packet.clone(), 0L)),
                totalBytes = packet.size,
                detectedSni = null
            )
        }

        val (sniStart, sniEnd, sniName) = sniLoc
        val slices = mutableListOf<FragmentSlice>()

        // Zone 0: Before SNI
        chunkZone(packet, 0, sniStart, config.beforeSniRange, config.delayMsRange, "before_sni", slices)

        // Zone 1: SNI Hostname
        chunkZone(packet, sniStart, sniEnd, config.sniRange, config.delayMsRange, "sni", slices)

        // Zone 2: After SNI
        chunkZone(packet, sniEnd, packet.size, config.afterSniRange, config.delayMsRange, "after_sni", slices)

        val totalBytes = slices.sumOf { it.payload.size }
        return SniFragmentPlan(
            slices = slices,
            totalBytes = totalBytes,
            detectedSni = sniName
        )
    }

    private fun chunkZone(
        data: ByteArray,
        start: Int,
        end: Int,
        range: Pair<Int, Int>,
        delayRange: Pair<Long, Long>,
        zoneName: String,
        out: MutableList<FragmentSlice>
    ) {
        if (start >= end) return

        val minChunk = if (range.first <= 0) 1 else range.first
        val maxChunk = if (range.second < minChunk) minChunk else range.second
        val minDelay = if (delayRange.first < 0L) 0L else delayRange.first
        val maxDelay = if (delayRange.second < minDelay) minDelay else delayRange.second

        val span = maxChunk - minChunk + 1
        val delaySpan = (maxDelay - minDelay + 1L).toInt()

        var offset = start
        var step = 0
        while (offset < end) {
            val chunkSize = minChunk + (step % span)
            val chunkEnd = Math.min(offset + chunkSize, end)
            val delayMs = minDelay + (if (delaySpan > 0) (step % delaySpan).toLong() else 0L)

            out.add(
                FragmentSlice(
                    zone = zoneName,
                    payload = data.copyOfRange(offset, chunkEnd),
                    delayMs = delayMs
                )
            )

            offset = chunkEnd
            step++
        }
    }
}
