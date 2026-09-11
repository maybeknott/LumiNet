package com.luminet.android.tunnel

import org.junit.Assert.assertArrayEquals
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertTrue
import org.junit.Test
import java.nio.ByteBuffer
import java.nio.ByteOrder

class TlsSessionObfuscatorTest {

    @Test
    fun testPadAndUnpadTicket() {
        val rawTicket = byteArrayOf(0xaa.toByte(), 0xbb.toByte(), 0xcc.toByte(), 0xdd.toByte(), 0xee.toByte())
        val padded = TicketPadder.padTicket(rawTicket)

        assertEquals(160, padded.size)
        assertArrayEquals(rawTicket, padded.copyOfRange(0, 5))

        val unpadded = TicketPadder.unpadTicket(padded)
        assertArrayEquals(rawTicket, unpadded)

        // 170 bytes -> 176
        val raw170 = ByteArray(170) { 0x11.toByte() }
        val padded176 = TicketPadder.padTicket(raw170)
        assertEquals(176, padded176.size)
        assertArrayEquals(raw170, TicketPadder.unpadTicket(padded176))
    }

    @Test
    fun testObfuscatedSessionStateRoundtrip() {
        val ticket = byteArrayOf(1, 2, 3, 4, 5, 6, 7, 8)
        val secret = ByteArray(32) { 0x42.toByte() }
        val state = ObfuscatedClientSessionState.create(
            ticket = ticket,
            vers = 0x0304,
            cipherSuite = 0x1301,
            masterSecret = secret,
            createdAt = 1710000000L,
            ageAdd = 12345L,
            useBy = 1710100000L
        )

        assertEquals(160, state.ticket.size)

        val serialized = state.serialize()
        val deserialized = ObfuscatedClientSessionState.deserialize(serialized)

        assertEquals(0x0304, deserialized.vers)
        assertEquals(0x1301, deserialized.cipherSuite)
        assertEquals(1710000000L, deserialized.createdAt)
        assertEquals(12345L, deserialized.ageAdd)
        assertArrayEquals(secret, deserialized.masterSecret)
        assertArrayEquals(ticket, TicketPadder.unpadTicket(deserialized.ticket))
    }

    @Test
    fun testTlsPassthroughDeflector() {
        val deflector = TlsPassthroughDeflector(
            passthroughAddress = "192.0.2.1:443",
            authorizedTokens = listOf("secret-auth-token-123")
        )

        assertFalse(deflector.shouldDeflect("secret-auth-token-123"))
        assertTrue(deflector.shouldDeflect("wrong-token"))
        assertTrue(deflector.shouldDeflect(null))
        assertTrue(deflector.shouldDeflect(""))

        val disabled = TlsPassthroughDeflector(null, emptyList())
        assertFalse(disabled.shouldDeflect(null))
    }

    @Test
    fun testParseEchConfigList() {
        val configBody = ByteBuffer.allocate(128).order(ByteOrder.BIG_ENDIAN)
        configBody.put(0x01.toByte()) // config_id
        configBody.putShort(0x0020.toShort()) // kem_id
        configBody.putShort(4.toShort()) // pk len
        configBody.put(byteArrayOf(0x10, 0x20, 0x30, 0x40)) // pk

        // Cipher suites
        configBody.putShort(4.toShort()) // cipher len
        configBody.putShort(0x0001.toShort()) // kdf
        configBody.putShort(0x0001.toShort()) // aead

        configBody.put(64.toByte()) // max name length
        val pubName = "cloudflare-ech.com".toByteArray(Charsets.UTF_8)
        configBody.put(pubName.size.toByte())
        configBody.put(pubName)

        val bodyBytes = configBody.array().copyOfRange(0, configBody.position())

        val entryBuf = ByteBuffer.allocate(4 + bodyBytes.size).order(ByteOrder.BIG_ENDIAN)
        entryBuf.putShort(0xfe0d.toShort()) // version
        entryBuf.putShort(bodyBytes.size.toShort())
        entryBuf.put(bodyBytes)
        val entryBytes = entryBuf.array()

        val listBuf = ByteBuffer.allocate(2 + entryBytes.size).order(ByteOrder.BIG_ENDIAN)
        listBuf.putShort(entryBytes.size.toShort())
        listBuf.put(entryBytes)
        val listBytes = listBuf.array()

        val configs = EchConfigParser.parseConfigList(listBytes)
        assertEquals(1, configs.size)
        val c = configs[0]
        assertEquals(0xfe0d, c.version)
        assertEquals(1, c.configId)
        assertEquals(0x0020, c.kemId)
        assertEquals("cloudflare-ech.com", c.publicName)
        assertEquals(1, c.cipherSuites.size)
        assertEquals(1, c.cipherSuites[0].kdfId)
    }
}
