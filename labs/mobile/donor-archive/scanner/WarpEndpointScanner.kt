package com.luminet.android.scanner

import java.nio.ByteBuffer
import java.nio.ByteOrder
import java.security.SecureRandom

/**
 * Cloudflare WARP Endpoint Scanner & WireGuard Handshake Prober.
 * Ported and unified from `ipscanner-main` and `warp-plus-master`.
 */
object WarpEndpointScanner {

    val WARP_PORTS = intArrayOf(
        500, 854, 859, 864, 878, 880, 890, 891, 894, 903,
        908, 928, 934, 939, 942, 943, 945, 946, 955, 968,
        987, 988, 1002, 1010, 1014, 1018, 1070, 1074, 1180, 1387,
        1701, 1843, 2371, 2408, 2506, 3138, 3476, 3581, 3854, 4177,
        4198, 4233, 4500, 5279, 5956, 7103, 7152, 7156, 7281, 7559,
        8319, 8742, 8854, 8886
    )

    val WARP_IPV4_PREFIXES = listOf(
        "162.159.192",
        "162.159.193",
        "162.159.195",
        "188.114.96",
        "188.114.97",
        "188.114.98",
        "188.114.99"
    )

    val WARP_IPV6_PREFIXES = listOf(
        "2606:4700:d0::",
        "2606:4700:d1::"
    )

    const val DEFAULT_PEER_PUBLIC_KEY = "bmXOC+F1FxEMF9dyiK2H5/1SUtzH0JuVo51h2wPfgyo="
    const val INITIATION_PACKET_LEN = 148
    const val RESPONSE_PACKET_LEN = 92

    data class WarpScanResult(
        val endpoint: String,
        val rttMs: Double,
        val jitterMs: Double,
        val lossPct: Double,
        val attempts: Int,
        val successfulAttempts: Int
    )

    private val random = SecureRandom()

    fun selectRandomWarpPort(): Int {
        return WARP_PORTS[random.nextInt(WARP_PORTS.size)]
    }

    fun generateCandidates(count: Int, useIpv6: Boolean = false): List<String> {
        val candidates = mutableListOf<String>()
        val prefixes = if (useIpv6) WARP_IPV6_PREFIXES else WARP_IPV4_PREFIXES

        for (i in 0 until count) {
            val prefix = prefixes[random.nextInt(prefixes.size)]
            val port = selectRandomWarpPort()
            val host = if (useIpv6) {
                "[$prefix${random.nextInt(65535).toString(16)}]:$port"
            } else {
                val hostOctet = 1 + random.nextInt(254)
                "$prefix.$hostOctet:$port"
            }
            candidates.add(host)
        }
        return candidates
    }

    /**
     * Builds a 148-byte WireGuard Noise_IK Initiation packet for ping probing.
     */
    fun buildInitiationPacket(senderIndex: Int = 28): ByteArray {
        val pkt = ByteArray(INITIATION_PACKET_LEN)
        val buf = ByteBuffer.wrap(pkt).order(ByteOrder.LITTLE_ENDIAN)

        // Type 1: Initiation
        buf.putInt(0, 1)
        // Sender Index
        buf.putInt(4, senderIndex)

        // Uncalibrated mock ephemeral key & encrypted static fields (filled with random bytes)
        val randBytes = ByteArray(148 - 8 - 16)
        random.nextBytes(randBytes)
        System.arraycopy(randBytes, 0, pkt, 8, randBytes.size)

        // MAC2 (16 bytes) left as zero
        for (i in 132 until 148) {
            pkt[i] = 0
        }

        return pkt
    }

    /**
     * Validates that an incoming packet is a valid 92-byte WireGuard Response packet matching our sender index.
     */
    fun validateResponse(packet: ByteArray, expectedSenderIndex: Int = 28): Boolean {
        if (packet.size < RESPONSE_PACKET_LEN) return false

        val buf = ByteBuffer.wrap(packet).order(ByteOrder.LITTLE_ENDIAN)
        val msgType = buf.getInt(0)
        if (msgType != 2) return false

        val receiverIndex = buf.getInt(8)
        return receiverIndex == expectedSenderIndex
    }

    /**
     * Ranks scan results prioritizing lowest loss, then lowest jitter, then lowest RTT.
     */
    fun rankEndpoints(results: List<WarpScanResult>): List<WarpScanResult> {
        return results.sortedWith(
            compareBy<WarpScanResult> { it.lossPct }
                .thenBy { it.jitterMs }
                .thenBy { it.rttMs }
        )
    }
}
