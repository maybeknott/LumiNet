package com.luminet.android.security

import org.json.JSONObject
import org.junit.Assert.assertEquals
import org.junit.Assert.assertNotNull
import org.junit.Assert.assertTrue
import org.junit.Assert.fail
import org.junit.Test
import java.io.IOException

class EncryptedPayloadEnvelopeTest {

    @Test
    fun testEncryptAndDecryptPayload() {
        val passphrase = "android-whitevpn-test-passphrase"
        val payload = "https://cdn.example.com/api/v1/config.json"

        val encryptedJson = EncryptedPayloadCodec.encrypt(payload.toByteArray(Charsets.UTF_8), passphrase)
        val root = JSONObject(encryptedJson)
        assertEquals(1, root.getInt("version"))
        assertEquals("AES-GCM", root.getString("algorithm"))
        assertEquals("base64url", root.getString("encoding"))
        assertTrue(root.getString("iv").isNotEmpty())
        assertTrue(root.getString("ciphertext").isNotEmpty())

        val decrypted = EncryptedPayloadCodec.decryptText(encryptedJson, passphrase)
        assertEquals(payload, decrypted)
    }

    @Test
    fun testDecryptWithWrongPassphraseThrows() {
        val encryptedJson = EncryptedPayloadCodec.encrypt("confidential".toByteArray(Charsets.UTF_8), "key-correct")
        try {
            EncryptedPayloadCodec.decrypt(encryptedJson, "key-wrong")
            fail("Expected IOException")
        } catch (_: IOException) {
            // expected
        }
    }

    @Test
    fun testParseAndEncryptIpList() {
        val raw = "192.0.2.1  198.51.100.1\n\n192.0.2.1 bad 300.1.1.1 1.1.1.1"
        val ips = EncryptedPayloadCodec.parsePlaintextIps(raw)
        assertEquals(listOf("192.0.2.1", "198.51.100.1", "1.1.1.1"), ips)

        val passphrase = "ip-list-key"
        val encrypted = EncryptedPayloadCodec.encryptIpList(ips, passphrase)
        val decrypted = EncryptedPayloadCodec.decryptIpList(encrypted, passphrase)
        assertEquals(ips, decrypted)
    }
}
