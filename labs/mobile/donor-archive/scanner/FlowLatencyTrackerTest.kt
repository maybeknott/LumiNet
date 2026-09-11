package com.luminet.android.scanner

import org.junit.Assert.assertEquals
import org.junit.Assert.assertNotNull
import org.junit.Assert.assertNull
import org.junit.Assert.assertTrue
import org.junit.Test
import java.nio.ByteBuffer
import java.nio.ByteOrder

class FlowLatencyTrackerTest {

    @Test
    fun testFlowHashSymmetry() {
        val hForward = FlowLatencyTracker.computeFlowHash("192.168.1.50", 12345, "1.1.1.1", 443)
        val hReverse = FlowLatencyTracker.computeFlowHash("1.1.1.1", 443, "192.168.1.50", 12345)
        assertEquals("Forward and reverse 4-tuples must hash symmetrically", hForward, hReverse)
    }

    @Test
    fun testFlowLatencyTracking() {
        val tracker = FlowLatencyTracker()

        val clientIp = "10.0.0.2"
        val clientPort = 50000
        val serverIp = "10.0.0.1"
        val serverPort = 80

        val tSyn = 1_000_000_000uL // 1s
        tracker.onSyn(clientIp, clientPort, serverIp, serverPort, tSyn)
        assertEquals(1, tracker.pendingCount())

        val tSynAck = 1_030_000_000uL // 1.030s (+30ms)
        val rttMs = tracker.onSynAck(serverIp, serverPort, clientIp, clientPort, tSynAck)

        assertNotNull(rttMs)
        assertEquals(30.0, rttMs!!, 0.001)
        assertEquals(0, tracker.pendingCount())

        val stats = tracker.stats
        assertEquals(1L, stats.sampleCount)
        assertEquals(30.0, stats.averageRttMs()!!, 0.001)
    }

    @Test
    fun testRawEventUnmarshal() {
        val raw = ByteArray(48)
        // IPv4-mapped 1.2.3.4
        raw[10] = 0xff.toByte()
        raw[11] = 0xff.toByte()
        raw[12] = 1
        raw[13] = 2
        raw[14] = 3
        raw[15] = 4

        // IPv4-mapped 5.6.7.8
        raw[26] = 0xff.toByte()
        raw[27] = 0xff.toByte()
        raw[28] = 5
        raw[29] = 6
        raw[30] = 7
        raw[31] = 8

        val buf = ByteBuffer.wrap(raw)
        buf.putShort(32, 12345.toShort())
        buf.putShort(34, 80.toShort())

        raw[36] = 1 // SYN
        raw[37] = 0 // ACK

        buf.order(ByteOrder.LITTLE_ENDIAN)
        buf.putLong(40, 2_000_000_000L)

        val pkt = FlowLatencyTracker.TcpProbePacket.fromRawEvent(raw)
        assertNotNull(pkt)
        assertEquals("1.2.3.4", pkt!!.srcIp)
        assertEquals(12345, pkt.srcPort)
        assertEquals("5.6.7.8", pkt.dstIp)
        assertEquals(80, pkt.dstPort)
        assertTrue(pkt.syn)

        val tracker = FlowLatencyTracker()
        assertNull(tracker.processPacket(pkt))
        assertEquals(1, tracker.pendingCount())
    }
}
