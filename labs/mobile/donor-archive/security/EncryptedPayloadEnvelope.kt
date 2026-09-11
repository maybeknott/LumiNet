package com.luminet.android.security

import org.json.JSONObject
import java.io.IOException
import java.security.MessageDigest
import java.util.Base64
import javax.crypto.Cipher
import javax.crypto.spec.GCMParameterSpec
import javax.crypto.spec.SecretKeySpec

data class EncryptedPayloadEnvelope(
    val version: Int,
    val algorithm: String,
    val encoding: String,
    val iv: String,
    val ciphertext: String
)

object EncryptedPayloadCodec {
    private const val AES_GCM_TAG_BITS = 128
    const val SUPPORTED_VERSION = 1
    const val SUPPORTED_ALGO = "AES-GCM"
    const val SUPPORTED_ENCODING = "base64url"

    fun deriveKey(passphrase: String): ByteArray {
        require(passphrase.isNotBlank()) { "Passphrase cannot be blank" }
        return MessageDigest.getInstance("SHA-256").digest(passphrase.toByteArray(Charsets.UTF_8))
    }

    fun encrypt(plaintext: ByteArray, passphrase: String): String {
        val key = deriveKey(passphrase)
        val cipher = Cipher.getInstance("AES/GCM/NoPadding")
        cipher.init(Cipher.ENCRYPT_MODE, SecretKeySpec(key, "AES"))
        val iv = cipher.iv
        val ciphertext = cipher.doFinal(plaintext)

        val encoder = Base64.getUrlEncoder().withoutPadding()
        val json = JSONObject().apply {
            put("version", SUPPORTED_VERSION)
            put("algorithm", SUPPORTED_ALGO)
            put("encoding", SUPPORTED_ENCODING)
            put("iv", encoder.encodeToString(iv))
            put("ciphertext", encoder.encodeToString(ciphertext))
        }
        return json.toString()
    }

    fun decrypt(payloadJson: String, passphrase: String): ByteArray {
        val key = deriveKey(passphrase)
        val root = JSONObject(payloadJson)
        val version = root.optInt("version")
        val algorithm = root.optString("algorithm")
        val encoding = root.optString("encoding")

        if (version != SUPPORTED_VERSION) {
            throw IOException("Unsupported envelope version: expected $SUPPORTED_VERSION, got $version")
        }
        if (algorithm != SUPPORTED_ALGO) {
            throw IOException("Unsupported envelope algorithm: expected $SUPPORTED_ALGO, got $algorithm")
        }
        if (encoding != SUPPORTED_ENCODING) {
            throw IOException("Unsupported envelope encoding: expected $SUPPORTED_ENCODING, got $encoding")
        }

        val iv = decodeUrlSafeBase64(root.getString("iv"))
        val ciphertext = decodeUrlSafeBase64(root.getString("ciphertext"))

        return runCatching {
            val cipher = Cipher.getInstance("AES/GCM/NoPadding")
            cipher.init(Cipher.DECRYPT_MODE, SecretKeySpec(key, "AES"), GCMParameterSpec(AES_GCM_TAG_BITS, iv))
            cipher.doFinal(ciphertext)
        }.getOrElse { error ->
            throw IOException("Cryptographic decryption failed: ${error.message}", error)
        }
    }

    fun decryptText(payloadJson: String, passphrase: String): String {
        return decrypt(payloadJson, passphrase).toString(Charsets.UTF_8)
    }

    fun parsePlaintextIps(text: String): List<String> {
        val seen = linkedSetOf<String>()
        text.split(Regex("\\s+"))
            .map { it.trim() }
            .filter { it.isNotBlank() }
            .filter { isValidIpv4(it) }
            .forEach { seen.add(it) }
        return seen.toList()
    }

    fun encryptIpList(ips: List<String>, passphrase: String): String {
        val text = ips.joinToString("\n")
        return encrypt(text.toByteArray(Charsets.UTF_8), passphrase)
    }

    fun decryptIpList(payloadJson: String, passphrase: String): List<String> {
        val text = decryptText(payloadJson, passphrase)
        val ips = parsePlaintextIps(text)
        if (ips.isEmpty()) {
            throw IOException("Decrypted IP list contained no usable IPv4 addresses")
        }
        return ips
    }

    private fun decodeUrlSafeBase64(value: String): ByteArray {
        val normalized = value.filterNot { it.isWhitespace() }
        require(normalized.isNotBlank()) { "Base64 string is blank" }
        return Base64.getUrlDecoder().decode(normalized)
    }

    private fun isValidIpv4(value: String): Boolean {
        val octets = value.split(".")
        return octets.size == 4 && octets.all { octet ->
            octet.toIntOrNull()?.let { it in 0..255 } == true
        }
    }
}
