package com.luminet.android.tunnel

import java.nio.ByteBuffer
import java.security.MessageDigest
import java.util.HashSet
import javax.crypto.Mac
import javax.crypto.spec.SecretKeySpec
import kotlin.math.abs

data class ReplayResistantConfig(
    val psk: ByteArray = "luminet-default-replay-psk-2026".toByteArray(Charsets.UTF_8),
    val maxSkewSecs: Long = 60,
    val maxTrackedNonces: Int = 4096
)

class ReplayResistantTunnelSession(
    val config: ReplayResistantConfig,
    clientRandom: ByteArray,
    serverRandom: ByteArray
) {
    private val sessionKey: ByteArray
    private var lastRemoteSeq: Long = 0
    private val seenNonces = HashSet<String>()

    init {
        val md = MessageDigest.getInstance("SHA-256")
        md.update(config.psk)
        md.update(clientRandom)
        md.update(serverRandom)
        sessionKey = md.digest()
    }

    fun sealPacket(sequence: Long, timestamp: Long, payload: ByteArray): ByteArray {
        val packet = ByteBuffer.allocate(8 + 8 + 12 + payload.size + 16)
        packet.putLong(sequence)
        packet.putLong(timestamp)

        val nonce = ByteArray(12)
        val seqBuf = ByteBuffer.allocate(8).putLong(sequence).array()
        val tsBuf = ByteBuffer.allocate(8).putLong(timestamp).array()
        for (i in 0 until 8) {
            nonce[i] = (seqBuf[i].toInt() xor sessionKey[i].toInt()).toByte()
        }
        for (i in 0 until 4) {
            nonce[8 + i] = (tsBuf[i].toInt() xor sessionKey[8 + i].toInt()).toByte()
        }
        packet.put(nonce)

        for (i in payload.indices) {
            val k = sessionKey[(i + (nonce[i % 12].toInt() and 0xff)) % sessionKey.size]
            packet.put((payload[i].toInt() xor k.toInt()).toByte())
        }

        val mac = Mac.getInstance("HmacSHA256")
        mac.init(SecretKeySpec(sessionKey, "HmacSHA256"))
        mac.update(packet.array(), 0, 28 + payload.size)
        val tag = mac.doFinal()

        packet.put(tag, 0, 16)
        return packet.array()
    }

    fun openPacket(packet: ByteArray, currentTime: Long): Triple<Long, Long, ByteArray> {
        if (packet.size < 28 + 16) {
            throw IllegalArgumentException("Packet too short")
        }

        val buf = ByteBuffer.wrap(packet)
        val sequence = buf.long
        val timestamp = buf.long

        val diff = abs(currentTime - timestamp)
        if (diff > config.maxSkewSecs) {
            throw SecurityException("Timestamp skew too large: $diff")
        }

        val nonce = ByteArray(12)
        buf.get(nonce)
        val nonceHex = nonce.joinToString("") { "%02x".format(it) }

        if (seenNonces.contains(nonceHex)) {
            throw SecurityException("Replay detected")
        }

        val bodyEnd = packet.size - 16
        val mac = Mac.getInstance("HmacSHA256")
        mac.init(SecretKeySpec(sessionKey, "HmacSHA256"))
        mac.update(packet, 0, bodyEnd)
        val expectedTag = mac.doFinal()

        for (i in 0 until 16) {
            if (packet[bodyEnd + i] != expectedTag[i]) {
                throw SecurityException("Integrity check failed")
            }
        }

        if (sequence <= lastRemoteSeq && lastRemoteSeq > 0) {
            throw SecurityException("Out of order sequence: $sequence <= $lastRemoteSeq")
        }

        val payloadLen = bodyEnd - 28
        val decrypted = ByteArray(payloadLen)
        for (i in 0 until payloadLen) {
            val k = sessionKey[(i + (nonce[i % 12].toInt() and 0xff)) % sessionKey.size]
            decrypted[i] = (packet[28 + i].toInt() xor k.toInt()).toByte()
        }

        if (seenNonces.size >= config.maxTrackedNonces) {
            seenNonces.clear()
        }
        seenNonces.add(nonceHex)
        lastRemoteSeq = sequence

        return Triple(sequence, timestamp, decrypted)
    }
}
