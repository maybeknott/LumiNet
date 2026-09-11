package com.luminet.android.tunnel

import java.nio.ByteBuffer
import java.security.SecureRandom

class MasqueAmneziaHybridTunnel(
    val contextId: Long,
    val amneziaConfig: AmneziaObfsConfig
) {
    private val masque = MasqueDatagramTunnel(contextId)
    private val random = SecureRandom()

    fun generateHandshakePreamble(initPayload: ByteArray): List<ByteArray> {
        val packets = mutableListOf<ByteArray>()

        // 1. Generate Jc junk packets
        for (i in 0 until amneziaConfig.jc) {
            val span = amneziaConfig.jmax - amneziaConfig.jmin
            val junkLen = amneziaConfig.jmin + (if (span > 0) random.nextInt(span) else 0)
            val junk = ByteArray(junkLen)
            random.nextBytes(junk)
            packets.add(junk)
        }

        // 2. Wrap initiation with H1 header and S1 padding
        val totalLen = 4 + initPayload.size + amneziaConfig.s1
        val buf = ByteBuffer.allocate(totalLen)
        buf.putInt(amneziaConfig.h1.toInt())
        buf.put(initPayload)
        if (amneziaConfig.s1 > 0) {
            val pad = ByteArray(amneziaConfig.s1)
            random.nextBytes(pad)
            buf.put(pad)
        }

        // Encapsulate into MASQUE capsule
        val capsule = masque.encodeDatagram(buf.array())
        packets.add(capsule)
        return packets
    }

    fun encapsulateData(ipPacket: ByteArray): ByteArray {
        val buf = ByteBuffer.allocate(4 + ipPacket.size)
        buf.putInt(amneziaConfig.h4.toInt())
        buf.put(ipPacket)
        return masque.encodeDatagram(buf.array())
    }

    fun decapsulateData(capsule: ByteArray): ByteArray? {
        val (ctx, payload) = masque.decodeDatagram(capsule) ?: return null
        if (ctx != contextId || payload.size < 4) return null

        val buf = ByteBuffer.wrap(payload)
        val h = buf.getInt().toLong() and 0xFFFFFFFFL
        if (h != (amneziaConfig.h4 and 0xFFFFFFFFL)) return null

        val ip = ByteArray(payload.size - 4)
        buf.get(ip)
        return ip
    }
}
