package com.luminet.android.tunnel

import java.nio.ByteBuffer
import java.nio.charset.StandardCharsets

/**
 * Supported relay forwarding networks.
 */
enum class RelayNetwork(val id: String) {
    TCP("tcp"),
    UDP("udp")
}

/**
 * Relay stream header defining egress tunnel destination.
 * Mirrors lumicore::relay::relay_stream_codec.
 */
data class RelayStreamHeader(
    val network: RelayNetwork,
    val host: String,
    val port: Int
) {
    /**
     * Encodes into ASCII wire format: `<network>@<host>$<port>\r`.
     */
    fun encodeV1(): ByteArray {
        val s = "${network.id}@$host\$$port\r"
        return s.toByteArray(StandardCharsets.UTF_8)
    }

    /**
     * Encodes into compact binary wire format:
     * Magic [0x52, 0x32] ('R2') + NetByte (1=TCP, 2=UDP) + Port (u16 BE) + HostLen (u8) + HostBytes
     */
    fun encodeV2(): ByteArray {
        val hostBytes = host.toByteArray(StandardCharsets.UTF_8)
        val clampedHostLen = hostBytes.size.coerceAtMost(255)
        val bb = ByteBuffer.allocate(6 + clampedHostLen)
        bb.put('R'.code.toByte())
        bb.put('2'.code.toByte())
        bb.put(if (network == RelayNetwork.TCP) 1.toByte() else 2.toByte())
        bb.putShort(port.toShort())
        bb.put(clampedHostLen.toByte())
        bb.put(hostBytes, 0, clampedHostLen)
        return bb.array()
    }

    companion object {
        /**
         * Decodes ASCII delimiter wire format.
         */
        fun decodeV1(src: ByteArray): Pair<RelayStreamHeader, Int> {
            require(src.isNotEmpty()) { "Empty buffer" }
            val crPos = src.indexOf('\r'.code.toByte())
            require(crPos != -1) { "Missing delimiter \\r" }

            val slice = src.copyOfRange(0, crPos)
            val atPos = slice.indexOf('@'.code.toByte())
            require(atPos != -1) { "Missing delimiter @" }

            val netStr = String(slice.copyOfRange(0, atPos), StandardCharsets.UTF_8).lowercase()
            val network = when (netStr) {
                "tcp" -> RelayNetwork.TCP
                "udp" -> RelayNetwork.UDP
                else -> throw IllegalArgumentException("Invalid relay network: $netStr")
            }

            val rest = slice.copyOfRange(atPos + 1, slice.size)
            val dollarPos = rest.indexOf('$'.code.toByte())
            require(dollarPos != -1) { "Missing delimiter $" }

            val host = String(rest.copyOfRange(0, dollarPos), StandardCharsets.UTF_8)
            val portStr = String(rest.copyOfRange(dollarPos + 1, rest.size), StandardCharsets.UTF_8)
            val port = portStr.toInt()

            return Pair(RelayStreamHeader(network, host, port), crPos + 1)
        }

        /**
         * Decodes compact binary wire format.
         */
        fun decodeV2(src: ByteArray): Pair<RelayStreamHeader, Int> {
            require(src.size >= 6) { "Buffer too short for relay v2 header" }
            require(src[0] == 'R'.code.toByte() && src[1] == '2'.code.toByte()) { "Invalid relay v2 magic" }

            val network = when (src[2].toInt()) {
                1 -> RelayNetwork.TCP
                2 -> RelayNetwork.UDP
                else -> throw IllegalArgumentException("Unknown relay network byte: ${src[2]}")
            }

            val bb = ByteBuffer.wrap(src, 3, src.size - 3)
            val port = bb.short.toInt() and 0xFFFF
            val hostLen = bb.get().toInt() and 0xFF
            val totalLen = 6 + hostLen

            require(src.size >= totalLen) { "Buffer truncated for relay v2 host" }
            val hostBytes = ByteArray(hostLen)
            bb.get(hostBytes)
            val host = String(hostBytes, StandardCharsets.UTF_8)

            return Pair(RelayStreamHeader(network, host, port), totalLen)
        }
    }
}
