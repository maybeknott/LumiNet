package com.luminet.android.tunnel

import org.junit.Assert.*
import org.junit.Test

class TcpDesyncTrackerTest {

    @Test
    fun testHandshakeProgressionAndDecoySchedule() {
        val connId = ConnId("192.168.1.100", 45678, "93.184.216.34", 443)
        val tracker = TcpDesyncTracker(connId)

        assertEquals(HandshakePhase.INITIAL, tracker.phase)

        // 1. Outbound SYN: seq=1000, ack=0
        val act1 = tracker.processOutbound(
            seq = 1000L,
            ack = 0L,
            isSyn = true,
            isAck = false,
            isRst = false,
            isFin = false,
            payloadLen = 0,
            currIdent = 100,
            fakeLen = 50
        )
        assertFalse(act1.scheduleDecoy)
        assertEquals(HandshakePhase.SYN_SENT, tracker.phase)
        assertEquals(1000L, tracker.synSeq)

        // 2. Inbound SYN-ACK: seq=5000, ack=1001
        val inAct1 = tracker.processInbound(
            seq = 5000L,
            ack = 1001L,
            isSyn = true,
            isAck = true,
            isRst = false,
            isFin = false,
            payloadLen = 0
        )
        assertFalse(inAct1.decoyAcknowledged)
        assertEquals(HandshakePhase.SYN_ACK_RECEIVED, tracker.phase)
        assertEquals(5000L, tracker.synAckSeq)

        // 3. Outbound ACK: seq=1001, ack=5001
        val act2 = tracker.processOutbound(
            seq = 1001L,
            ack = 5001L,
            isSyn = false,
            isAck = true,
            isRst = false,
            isFin = false,
            payloadLen = 0,
            currIdent = 100,
            fakeLen = 50
        )
        assertTrue(act2.scheduleDecoy)
        assertEquals(951L, act2.decoySeq) // 1000 + 1 - 50 = 951
        assertEquals(101, act2.newIdent)
        assertEquals(HandshakePhase.DECOY_INJECTED, tracker.phase)

        // 4. Inbound ACK for decoy: seq=5001, ack=1001
        val inAct2 = tracker.processInbound(
            seq = 5001L,
            ack = 1001L,
            isSyn = false,
            isAck = true,
            isRst = false,
            isFin = false,
            payloadLen = 0
        )
        assertTrue(inAct2.decoyAcknowledged)
        assertEquals(HandshakePhase.DECOY_ACKNOWLEDGED, tracker.phase)
    }

    @Test
    fun testInvalidSequenceTransitionsToTerminated() {
        val connId = ConnId("10.0.0.2", 12345, "1.1.1.1", 443)
        val tracker = TcpDesyncTracker(connId)

        // Invalid: SYN with non-zero ACK
        try {
            tracker.processOutbound(
                seq = 100L,
                ack = 50L,
                isSyn = true,
                isAck = false,
                isRst = false,
                isFin = false,
                payloadLen = 0,
                currIdent = 1,
                fakeLen = 10
            )
            fail("Expected IllegalArgumentException")
        } catch (e: IllegalArgumentException) {
            assertEquals(HandshakePhase.TERMINATED, tracker.phase)
        }
    }
}
