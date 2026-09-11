package com.luminet.android.tunnel

import org.junit.Assert.*
import org.junit.Test

class CovertDeadDropProtocolTest {

    @Test
    fun testDeriveBlobKey() {
        val raw = "secret_passphrase_test_123"
        val key = CovertDeadDropProtocol.deriveBlobKey(raw)
        assertEquals(32, key.size)

        val sid = ByteArray(16) { 0x11.toByte() }
        val lane0 = CovertDeadDropProtocol.deriveMuxLaneKeyV4(raw, sid, CovertDeadDropProtocol.DIRECTION_UP, "client-1", "run-1", 0)
        val lane1 = CovertDeadDropProtocol.deriveMuxLaneKeyV4(raw, sid, CovertDeadDropProtocol.DIRECTION_UP, "client-1", "run-1", 1)
        assertEquals(32, lane0.size)
        assertEquals(32, lane1.size)
        assertFalse(lane0.contentEquals(lane1))
    }

    @Test
    fun testSealAndOpenRoundtrip() {
        val key = ByteArray(32) { (it + 1).toByte() }
        val sid = "1234567890abcdef".toByteArray(Charsets.US_ASCII)
        val plaintext = "Hello Covert Tunneling Over Dead-Drop Storage".toByteArray(Charsets.UTF_8)
        val seq = 777L

        val sealed = CovertDeadDropProtocol.sealBlobEnvelope(
            key = key,
            sid = sid,
            direction = CovertDeadDropProtocol.DIRECTION_UP,
            sequence = seq,
            plaintext = plaintext,
            isFinal = false
        )

        assertEquals(39 + plaintext.size + 16, sealed.size)
        val (env, decrypted) = CovertDeadDropProtocol.openBlobEnvelope(key, sealed)

        assertArrayEquals(sid, env.sessionId)
        assertEquals(CovertDeadDropProtocol.DIRECTION_UP, env.direction)
        assertEquals(seq, env.sequence)
        assertEquals(CovertDeadDropProtocol.FLAG_DATA, env.flags)
        assertEquals(plaintext.size, env.plaintextLen)
        assertArrayEquals(plaintext, decrypted)
    }

    @Test
    fun testFinalEnvelope() {
        val key = ByteArray(32) { 0x55.toByte() }
        val sid = ByteArray(16) { 0xAA.toByte() }
        val plaintext = "EOF".toByteArray(Charsets.UTF_8)

        val sealed = CovertDeadDropProtocol.sealBlobEnvelope(
            key = key,
            sid = sid,
            direction = CovertDeadDropProtocol.DIRECTION_DOWN,
            sequence = 100L,
            plaintext = plaintext,
            isFinal = true
        )

        val (env, decrypted) = CovertDeadDropProtocol.openBlobEnvelope(key, sealed)
        assertEquals(CovertDeadDropProtocol.FLAG_FINAL, env.flags)
        assertArrayEquals(plaintext, decrypted)
    }

    @Test
    fun testCoalesceDecisions() {
        assertEquals(CovertDeadDropProtocol.CoalesceTier.INTERACTIVE, CovertDeadDropProtocol.evaluateTier(100))
        assertEquals(CovertDeadDropProtocol.CoalesceTier.MEDIUM, CovertDeadDropProtocol.evaluateTier(16 * 1024))
        assertEquals(CovertDeadDropProtocol.CoalesceTier.BULK, CovertDeadDropProtocol.evaluateTier(128 * 1024))
        assertEquals(CovertDeadDropProtocol.CoalesceTier.FORCED_BULK, CovertDeadDropProtocol.evaluateTier(512 * 1024))

        assertFalse(CovertDeadDropProtocol.shouldFlush(100, 5L))
        assertTrue(CovertDeadDropProtocol.shouldFlush(100, 16L))
        assertTrue(CovertDeadDropProtocol.shouldFlush(300 * 1024, 1L))
    }
}
