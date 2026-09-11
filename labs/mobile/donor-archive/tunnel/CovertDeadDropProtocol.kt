package com.luminet.android.tunnel

import java.nio.ByteBuffer
import java.nio.ByteOrder
import javax.crypto.Cipher
import javax.crypto.Mac
import javax.crypto.spec.GCMParameterSpec
import javax.crypto.spec.SecretKeySpec

/**
 * Covert Dead-Drop Binary Framing & AEAD Protocol (SKB1) for Android clients.
 * Originates from Skirk-main and unified into LumiNet.
 */
object CovertDeadDropProtocol {

    val ENVELOPE_MAGIC = "SKB1".toByteArray(Charsets.US_ASCII)
    const val ENVELOPE_VER: Byte = 1
    const val HEADER_LEN = 39
    const val KEY_LEN = 32
    const val MAX_SEQUENCE = (1L shl 56) - 1L

    const val DIRECTION_UP: Byte = 1
    const val DIRECTION_DOWN: Byte = 2
    const val FLAG_DATA: Byte = 0
    const val FLAG_FINAL: Byte = 1

    const val INTERACTIVE_THRESHOLD = 8 * 1024
    const val BULK_THRESHOLD = 64 * 1024
    const val FORCED_BULK_THRESHOLD = 256 * 1024

    data class BlobEnvelope(
        val sessionId: ByteArray,
        val direction: Byte,
        val sequence: Long,
        val flags: Byte,
        val plaintextLen: Int,
        val ciphertext: ByteArray
    ) {
        override fun equals(other: Any?): Boolean {
            if (this === other) return true
            if (javaClass != other?.javaClass) return false
            other as BlobEnvelope
            return direction == other.direction &&
                    sequence == other.sequence &&
                    flags == other.flags &&
                    plaintextLen == other.plaintextLen &&
                    sessionId.contentEquals(other.sessionId) &&
                    ciphertext.contentEquals(other.ciphertext)
        }

        override fun hashCode(): Int {
            var result = sessionId.contentHashCode()
            result = 31 * result + direction.toInt()
            result = 31 * result + sequence.hashCode()
            result = 31 * result + flags.toInt()
            result = 31 * result + plaintextLen
            result = 31 * result + ciphertext.contentHashCode()
            return result
        }
    }

    /**
     * Computes the 12-byte AES-GCM nonce:
     * Bytes 0..4: sid[0..4]
     * Byte 4: direction
     * Bytes 5..12: 7 bytes of sequence (big-endian)
     */
    fun computeNonce(sid: ByteArray, direction: Byte, sequence: Long): ByteArray {
        val out = ByteArray(12)
        System.arraycopy(sid, 0, out, 0, 4)
        out[4] = direction
        for (i in 0..6) {
            out[11 - i] = ((sequence ushr (8 * i)) and 0xFFL).toByte()
        }
        return out
    }

    /**
     * Derives a 32-byte key from a secret string using HKDF-SHA256 or hex/base64 prefix decoding.
     */
    fun deriveBlobKey(secret: String): ByteArray {
        val trimmed = secret.trim()
        if (trimmed.startsWith("hex:")) {
            val hexStr = trimmed.substring(4)
            val bytes = ByteArray(hexStr.length / 2)
            for (i in bytes.indices) {
                val index = i * 2
                bytes[i] = hexStr.substring(index, index + 2).toInt(16).toByte()
            }
            return bytes
        }
        if (trimmed.startsWith("base64:")) {
            return android.util.Base64.decode(trimmed.substring(7), android.util.Base64.DEFAULT)
        }
        return hkdfSha256(trimmed.toByteArray(Charsets.UTF_8), "skirk-v1-static-salt".toByteArray(Charsets.UTF_8), "skirk-blobq-aead-key".toByteArray(Charsets.UTF_8), KEY_LEN)
    }

    /**
     * Derives multi-lane subkeys for a session, client ID, run ID, and lane index.
     */
    fun deriveMuxLaneKeyV4(
        secret: String,
        sid: ByteArray,
        direction: Byte,
        clientId: String,
        runId: String,
        lane: Int
    ): ByteArray {
        val base = deriveBlobKey(secret)
        val info = ByteBuffer.allocate(32 + sid.size + clientId.length + runId.length + 6)
        info.put("skirk-mux-lane-aead-v4".toByteArray(Charsets.UTF_8))
        info.put(sid)
        info.put(direction)
        info.put(clientId.toByteArray(Charsets.UTF_8))
        info.put(0.toByte())
        info.put(runId.toByteArray(Charsets.UTF_8))
        info.put(0.toByte())
        info.put(lane.toByte())
        return hkdfSha256(base, "skirk-v4-mux-lane-salt".toByteArray(Charsets.UTF_8), info.array(), KEY_LEN)
    }

    private fun hkdfSha256(ikm: ByteArray, salt: ByteArray, info: ByteArray, length: Int): ByteArray {
        val mac = Mac.getInstance("HmacSHA256")
        mac.init(SecretKeySpec(salt, "HmacSHA256"))
        val prk = mac.doFinal(ikm)

        val out = ByteArray(length)
        var previous = ByteArray(0)
        var offset = 0
        var counter = 1.toByte()

        while (offset < length) {
            mac.init(SecretKeySpec(prk, "HmacSHA256"))
            mac.update(previous)
            mac.update(info)
            mac.update(counter)
            previous = mac.doFinal()
            val chunkLen = Math.min(previous.size, length - offset)
            System.arraycopy(previous, 0, out, offset, chunkLen)
            offset += chunkLen
            counter++
        }
        return out
    }

    /**
     * Seals plaintext into an authenticated SKB1 envelope using AES-256-GCM.
     */
    fun sealBlobEnvelope(
        key: ByteArray,
        sid: ByteArray,
        direction: Byte,
        sequence: Long,
        plaintext: ByteArray,
        isFinal: Boolean
    ): ByteArray {
        val flags = if (isFinal) FLAG_FINAL else FLAG_DATA
        val ciphertextLen = plaintext.size + 16 // GCM 128-bit tag

        val header = ByteBuffer.allocate(HEADER_LEN).order(ByteOrder.BIG_ENDIAN)
        header.put(ENVELOPE_MAGIC)
        header.put(ENVELOPE_VER)
        header.put(sid, 0, 16)
        header.put(direction)
        header.put(flags)
        header.putLong(sequence)
        header.putInt(plaintext.size)
        header.putInt(ciphertextLen)
        val headerBytes = header.array()

        val nonce = computeNonce(sid, direction, sequence)
        val cipher = Cipher.getInstance("AES/GCM/NoPadding")
        cipher.init(Cipher.ENCRYPT_MODE, SecretKeySpec(key, "AES"), GCMParameterSpec(128, nonce))
        cipher.updateAAD(headerBytes)
        val ciphertext = cipher.doFinal(plaintext)

        val out = ByteArray(HEADER_LEN + ciphertext.size)
        System.arraycopy(headerBytes, 0, out, 0, HEADER_LEN)
        System.arraycopy(ciphertext, 0, out, HEADER_LEN, ciphertext.size)
        return out
    }

    /**
     * Opens an authenticated SKB1 envelope and decrypts the payload.
     */
    fun openBlobEnvelope(key: ByteArray, data: ByteArray): Pair<BlobEnvelope, ByteArray> {
        if (data.size < HEADER_LEN) {
            throw IllegalArgumentException("envelope too short: ${data.size} < $HEADER_LEN")
        }

        val buf = ByteBuffer.wrap(data).order(ByteOrder.BIG_ENDIAN)
        val magic = ByteArray(4)
        buf.get(magic)
        if (!magic.contentEquals(ENVELOPE_MAGIC)) {
            throw IllegalArgumentException("bad envelope magic")
        }

        val ver = buf.get()
        if (ver != ENVELOPE_VER) {
            throw IllegalArgumentException("unsupported envelope version: $ver")
        }

        val sid = ByteArray(16)
        buf.get(sid)
        val direction = buf.get()
        val flags = buf.get()
        val sequence = buf.getLong()
        val plaintextLen = buf.getInt()
        val ciphertextLen = buf.getInt()

        if (ciphertextLen != data.size - HEADER_LEN) {
            throw IllegalArgumentException("ciphertext length mismatch")
        }

        val headerBytes = data.copyOfRange(0, HEADER_LEN)
        val ciphertext = data.copyOfRange(HEADER_LEN, data.size)

        val nonce = computeNonce(sid, direction, sequence)
        val cipher = Cipher.getInstance("AES/GCM/NoPadding")
        cipher.init(Cipher.DECRYPT_MODE, SecretKeySpec(key, "AES"), GCMParameterSpec(128, nonce))
        cipher.updateAAD(headerBytes)
        val plaintext = cipher.doFinal(ciphertext)

        if (plaintext.size != plaintextLen) {
            throw IllegalArgumentException("plaintext length mismatch")
        }

        val env = BlobEnvelope(
            sessionId = sid,
            direction = direction,
            sequence = sequence,
            flags = flags,
            plaintextLen = plaintextLen,
            ciphertext = ciphertext
        )
        return Pair(env, plaintext)
    }

    enum class CoalesceTier {
        INTERACTIVE,
        MEDIUM,
        BULK,
        FORCED_BULK
    }

    fun evaluateTier(bufferedBytes: Int): CoalesceTier {
        return when {
            bufferedBytes < INTERACTIVE_THRESHOLD -> CoalesceTier.INTERACTIVE
            bufferedBytes < BULK_THRESHOLD -> CoalesceTier.MEDIUM
            bufferedBytes < FORCED_BULK_THRESHOLD -> CoalesceTier.BULK
            else -> CoalesceTier.FORCED_BULK
        }
    }

    fun shouldFlush(bufferedBytes: Int, ageMs: Long): Boolean {
        if (bufferedBytes == 0) return false
        if (bufferedBytes >= FORCED_BULK_THRESHOLD) return true
        val maxAgeMs = when (evaluateTier(bufferedBytes)) {
            CoalesceTier.INTERACTIVE -> 15L
            CoalesceTier.MEDIUM -> 75L
            CoalesceTier.BULK -> 250L
            CoalesceTier.FORCED_BULK -> 1000L
        }
        return ageMs >= maxAgeMs
    }
}
