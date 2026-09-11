package com.luminet.android.tunnel

import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertNotNull
import org.junit.Assert.assertNull
import org.junit.Assert.assertTrue
import org.junit.Test
import java.nio.ByteBuffer
import java.nio.ByteOrder

class TunBridgeManagerTest {

    @Test
    fun `fake ip mapping allocates in 198 18 subnet and remains consistent`() {
        val manager = TunBridgeManager()
        val ip1 = manager.getFakeIp("example.com")
        assertTrue(ip1.startsWith("198.18."))

        val ip2 = manager.getFakeIp("example.com")
        assertEquals(ip1, ip2)

        val host = manager.getHostname(ip1)
        assertEquals("example.com", host)

        val ipDiff = manager.getFakeIp("google.com")
        assertTrue(ipDiff.startsWith("198.18."))
        assertTrue(ip1 != ipDiff)

        val stats = manager.getStats()
        assertEquals(2, stats.activeMappings)
    }

    @Test
    fun `bridge lifecycle manages file descriptor and states`() {
        val manager = TunBridgeManager()
        assertFalse(manager.isBridgeActive())

        // Invalid FD fails
        val failResult = manager.startBridge(-1)
        assertTrue(failResult.isFailure)

        // Valid FD succeeds
        val startResult = manager.startBridge(42)
        assertTrue(startResult.isSuccess)
        assertTrue(manager.isBridgeActive())

        // Stop succeeds
        val stopResult = manager.stopBridge()
        assertTrue(stopResult.isSuccess)
        assertFalse(manager.isBridgeActive())
    }

    @Test
    fun `parse and synthesize DNS wire packets`() {
        val manager = TunBridgeManager()

        // Wire DNS query for "cdn.example.org"
        val queryBuf = ByteBuffer.allocate(64).order(ByteOrder.BIG_ENDIAN)
        queryBuf.putShort(0x55AA.toShort()) // ID
        queryBuf.putShort(0x0100.toShort()) // Flags (standard query)
        queryBuf.putShort(1.toShort())      // QDCOUNT
        queryBuf.putShort(0.toShort())      // ANCOUNT
        queryBuf.putShort(0.toShort())      // NSCOUNT
        queryBuf.putShort(0.toShort())      // ARCOUNT

        // QNAME: 3 cdn 7 example 3 org 0
        queryBuf.put(3.toByte())
        queryBuf.put("cdn".toByteArray(Charsets.UTF_8))
        queryBuf.put(7.toByte())
        queryBuf.put("example".toByteArray(Charsets.UTF_8))
        queryBuf.put(3.toByte())
        queryBuf.put("org".toByteArray(Charsets.UTF_8))
        queryBuf.put(0.toByte())

        queryBuf.putShort(1.toShort()) // QTYPE A
        queryBuf.putShort(1.toShort()) // QCLASS IN

        val queryBytes = ByteArray(queryBuf.position())
        queryBuf.rewind()
        queryBuf.get(queryBytes)

        val parsedHost = manager.parseDnsQuery(queryBytes)
        assertEquals("cdn.example.org", parsedHost)

        val fakeIp = "198.18.1.10"
        val respBytes = manager.buildDnsResponse(queryBytes, fakeIp)
        assertNotNull(respBytes)

        val respBuf = ByteBuffer.wrap(respBytes).order(ByteOrder.BIG_ENDIAN)
        assertEquals(0x55AA.toShort(), respBuf.getShort(0))
        val respFlags = respBuf.getShort(2).toInt() and 0xFFFF
        assertTrue((respFlags and 0x8000) != 0) // QR = 1
        assertEquals(1.toShort(), respBuf.getShort(6)) // ANCOUNT = 1

        // Verify last 4 bytes match fake IP
        val tailIp = ByteArray(4)
        System.arraycopy(respBytes, respBytes.size - 4, tailIp, 0, 4)
        assertEquals(198.toByte(), tailIp[0])
        assertEquals(18.toByte(), tailIp[1])
        assertEquals(1.toByte(), tailIp[2])
        assertEquals(10.toByte(), tailIp[3])
    }
}
