package com.luminet.android.tunnel

import java.nio.ByteBuffer
import java.security.SecureRandom
import javax.crypto.Mac
import javax.crypto.spec.SecretKeySpec

enum class HybridShadowCipher {
    AEAD_AES_256_GCM,
    AEAD_CHACHA20_POLY1305
}

data class HybridShadowConfig(
    val cipher: HybridShadowCipher = HybridShadowCipher.AEAD_AES_256_GCM,
    val psk: ByteArray,
    val saltLength: Int = 32,
    val replayWindowSecs: Long = 120
)

class HybridShadowV2Transport(private val config: HybridShadowConfig) {
    private val saltHistory = mutableMapOf<String, Long>()
    private val random = SecureRandom()

    fun generateSalt(): ByteArray {
        val salt = ByteArray(config.saltLength)
        random.nextBytes(salt)
        return salt
    }

    fun deriveSubkey(salt: ByteArray): ByteArray {
        val mac = Mac.getInstance("HmacSHA256")
        mac.init(SecretKeySpec(config.psk, "HmacSHA256"))
        mac.update(salt)
        return mac.doFinal("hybrid-shadow-v2-subkey".toByteArray())
    }

    @Synchronized
    fun registerSalt(salt: ByteArray, nowSecs: Long): Boolean {
        // Prune stale
        val cutoff = nowSecs - config.replayWindowSecs
        val iterator = saltHistory.entries.iterator()
        while (iterator.hasNext()) {
            if (iterator.next().value < cutoff) {
                iterator.remove()
            }
        }

        val key = salt.joinToString("") { "%02x".format(it) }
        if (saltHistory.containsKey(key)) {
            return false // Replay
        }
        saltHistory[key] = nowSecs
        return true
    }

    fun framePayload(salt: ByteArray, payload: ByteArray): ByteArray {
        val buf = ByteBuffer.allocate(1 + salt.size + 2 + payload.size)
        buf.put(salt.size.toByte())
        buf.put(salt)
        buf.putShort(payload.size.toShort())
        buf.put(payload)
        return buf.array()
    }

    fun unframePayload(data: ByteArray): Pair<ByteArray, ByteArray>? {
        if (data.size < 3) return null
        val saltLen = data[0].toInt() and 0xFF
        if (data.size < 1 + saltLen + 2) return null

        val salt = data.copyOfRange(1, 1 + saltLen)
        val pLen = ((data[1 + saltLen].toInt() and 0xFF) shl 8) or (data[2 + saltLen].toInt() and 0xFF)
        val start = 3 + saltLen
        if (data.size < start + pLen) return null

        val payload = data.copyOfRange(start, start + pLen)
        return Pair(salt, payload)
    }
}
