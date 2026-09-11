package com.luminet.android.tunnel

import org.junit.Assert.*
import org.junit.Test

class SniSpoofingClientTest {

    @Test
    fun testComputeOutOfWindowSeq() {
        val isn = 1000L
        val payloadLen = 100
        val seq = SniSpoofingClient.computeOutOfWindowSeq(isn, payloadLen)
        assertEquals(901L, seq) // 1000 + 1 - 100 = 901

        // Wraparound check
        val smallIsn = 10L
        val bigLen = 50
        val wrapSeq = SniSpoofingClient.computeOutOfWindowSeq(smallIsn, bigLen)
        assertEquals(0xFFFFFFFFL - 38L, wrapSeq)
    }

    @Test
    fun testValidSni() {
        assertTrue(SniSpoofingClient.isValidSni("auth.vercel.com"))
        assertTrue(SniSpoofingClient.isValidSni("www.speedtest.net"))
        assertFalse(SniSpoofingClient.isValidSni(""))
        assertFalse(SniSpoofingClient.isValidSni(".invalid.com"))
        assertFalse(SniSpoofingClient.isValidSni("invalid..com"))
        assertFalse(SniSpoofingClient.isValidSni("invalid-.com"))
    }

    @Test
    fun testTcpHandshakeTrackerLifecycle() {
        val tracker = SniSpoofingClient.TcpDesyncTracker(
            "192.168.1.50", "188.114.98.0", 54321, 443
        )

        // Outbound SYN
        val plan1 = tracker.processOutbound(20000L, 0L, isSyn = true, isAck = false, currIdent = 100, fakeLen = 517)
        assertFalse(plan1.scheduleDecoy)
        assertEquals(SniSpoofingClient.HandshakePhase.SYN_SENT, tracker.phase)

        // Inbound SYN-ACK
        val ackRecv1 = tracker.processInbound(60000L, 20001L, isSyn = true, isAck = true)
        assertFalse(ackRecv1)
        assertEquals(SniSpoofingClient.HandshakePhase.SYN_ACK_RECEIVED, tracker.phase)

        // Outbound ACK
        val plan2 = tracker.processOutbound(20001L, 60001L, isSyn = false, isAck = true, currIdent = 100, fakeLen = 517)
        assertTrue(plan2.scheduleDecoy)
        assertEquals(19484L, plan2.decoySeq) // (20000 + 1) - 517 = 19484
        assertEquals(101, plan2.newIdent)
        assertEquals(SniSpoofingClient.HandshakePhase.DECOY_INJECTED, tracker.phase)

        // Inbound ACK for Decoy
        val ackRecv2 = tracker.processInbound(60001L, 20001L, isSyn = false, isAck = true)
        assertTrue(ackRecv2)
        assertEquals(SniSpoofingClient.HandshakePhase.DECOY_ACKNOWLEDGED, tracker.phase)
    }

    @Test
    fun testClientResponseRoundTrip() {
        val payload = "GET / HTTP/1.1\r\nHost: target.com\r\n\r\n".toByteArray(Charsets.UTF_8)
        val envelope = SniSpoofingClient.buildClientResponseWith(payload)
        assertEquals(11 + payload.size, envelope.size)

        val parsed = SniSpoofingClient.parseClientResponse(envelope)
        assertArrayEquals(payload, parsed)
    }
}

