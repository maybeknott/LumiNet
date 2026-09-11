package com.luminet.android.tunnel

import org.junit.Assert.*
import org.junit.Test

class TacticalTunnelSessionTest {

    @Test
    fun testKeyDerivationDeterminism() {
        val seed = ByteArray(16) { it.toByte() }
        val keyword = "tactical_android_keyword".toByteArray(Charsets.UTF_8)
        val k1 = TacticalTunnelSession.deriveKey(seed, keyword, TacticalTunnelSession.OBFUSCATE_CLIENT_TO_SERVER_IV)
        val k2 = TacticalTunnelSession.deriveKey(seed, keyword, TacticalTunnelSession.OBFUSCATE_CLIENT_TO_SERVER_IV)
        assertArrayEquals(k1, k2)

        val k3 = TacticalTunnelSession.deriveKey(seed, keyword, TacticalTunnelSession.OBFUSCATE_SERVER_TO_CLIENT_IV)
        assertFalse(k1.contentEquals(k3))
    }

    @Test
    fun testStreamCipherRoundtrip() {
        val key = "cipher_key_abc".toByteArray(Charsets.UTF_8)
        val enc = TacticalTunnelSession.StreamCipher(key)
        val dec = TacticalTunnelSession.StreamCipher(key)

        val msg = "Tactical payload to encrypt and decrypt".toByteArray(Charsets.UTF_8)
        val buf = msg.clone()

        enc.applyKeyStream(buf)
        assertFalse(msg.contentEquals(buf))

        dec.applyKeyStream(buf)
        assertArrayEquals(msg, buf)
    }

    @Test
    fun testSessionObfuscatorRoundtrip() {
        val keyword = "session_master_key".toByteArray(Charsets.UTF_8)
        val seed = ByteArray(16) { (it * 3).toByte() }
        val padding = "PADDING_RANDOM_FIXTURE_DATA".toByteArray(Charsets.UTF_8)

        val client = TacticalTunnelSession.SessionObfuscator.createClient(keyword, seed, padding.size)
        val preamble = client.generateClientPreamble(padding)

        val (server, recPadding) = TacticalTunnelSession.SessionObfuscator.createServerFromPreamble(keyword, preamble)
        assertArrayEquals(padding, recPadding)
        assertArrayEquals(seed, server.seed)

        // Stream c2s
        val c2sPayload = "REQ_PACKET_001".toByteArray(Charsets.UTF_8)
        val buf1 = c2sPayload.clone()
        client.obfuscateClientToServer(buf1)
        assertFalse(c2sPayload.contentEquals(buf1))
        server.obfuscateClientToServer(buf1)
        assertArrayEquals(c2sPayload, buf1)

        // Stream s2c
        val s2cPayload = "RESP_PACKET_200_OK".toByteArray(Charsets.UTF_8)
        val buf2 = s2cPayload.clone()
        server.obfuscateServerToClient(buf2)
        assertFalse(s2cPayload.contentEquals(buf2))
        client.obfuscateServerToClient(buf2)
        assertArrayEquals(s2cPayload, buf2)
    }

    @Test(expected = Exception::class)
    fun testCorruptedPreambleMagicFails() {
        val keyword = "key".toByteArray(Charsets.UTF_8)
        val seed = ByteArray(16) { 1 }
        val client = TacticalTunnelSession.SessionObfuscator.createClient(keyword, seed, 4)
        val preamble = client.generateClientPreamble(ByteArray(4) { 0xAA.toByte() })

        // Corrupt magic
        preamble[16] = (preamble[16].toInt() xor 0xFF).toByte()
        TacticalTunnelSession.SessionObfuscator.createServerFromPreamble(keyword, preamble)
    }

    @Test
    fun testTacticalEngineFiltering() {
        val defaultProfile = TacticalTunnelSession.TacticalProfile(
            ttlMs = 3600000L,
            parameters = mapOf("timeout_ms" to "4000", "pool" to "2")
        )
        val engine = TacticalTunnelSession.TacticalEngine(defaultProfile)

        engine.addFilter(
            TacticalTunnelSession.TacticalFilter(
                regions = listOf("IR", "CN"),
                asns = listOf(12345L),
                maxLatencyMs = null,
                profile = TacticalTunnelSession.TacticalProfile(
                    ttlMs = 1800000L,
                    parameters = mapOf("timeout_ms" to "10000", "pool" to "6", "tactics" to "FRONTED")
                )
            )
        )

        // Default query
        val p1 = engine.resolveProfile("US", 999L, 50L, true)
        assertEquals("4000", p1.parameters["timeout_ms"])
        assertNull(p1.parameters["tactics"])

        // Filtered query
        val p2 = engine.resolveProfile("IR", 12345L, 220L, true)
        assertEquals("10000", p2.parameters["timeout_ms"])
        assertEquals("6", p2.parameters["pool"])
        assertEquals("FRONTED", p2.parameters["tactics"])
        assertNotEquals(p1.tag, p2.tag)
    }
}
