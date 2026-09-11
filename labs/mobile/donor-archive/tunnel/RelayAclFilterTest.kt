package com.luminet.android.tunnel

import org.junit.Assert.assertArrayEquals
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertNotNull
import org.junit.Assert.assertNull
import org.junit.Assert.assertTrue
import org.junit.Test
import java.net.InetAddress

class RelayAclFilterTest {

    @Test
    fun testSourceWhitelistAllowedAndBlocked() {
        val filter = RelayAclFilter()

        // Cloudflare edge IPs
        val cf1 = InetAddress.getByName("104.16.24.5")
        val cf2 = InetAddress.getByName("172.67.182.11")
        val cf3 = InetAddress.getByName("162.158.5.10")
        val cf4 = InetAddress.getByName("198.41.130.1")
        val cfV6 = InetAddress.getByName("2606:4700:3033::6815:1805")

        assertTrue(filter.isSourceAllowed(cf1))
        assertTrue(filter.isSourceAllowed(cf2))
        assertTrue(filter.isSourceAllowed(cf3))
        assertTrue(filter.isSourceAllowed(cf4))
        assertTrue(filter.isSourceAllowed(cfV6))

        // Non-permitted sources
        val bad1 = InetAddress.getByName("8.8.8.8")
        val bad2 = InetAddress.getByName("185.199.108.153")
        val bad3 = InetAddress.getByName("192.168.1.100")
        val badV6 = InetAddress.getByName("2001:4860:4860::8888")

        assertFalse(filter.isSourceAllowed(bad1))
        assertFalse(filter.isSourceAllowed(bad2))
        assertFalse(filter.isSourceAllowed(bad3))
        assertFalse(filter.isSourceAllowed(badV6))
    }

    @Test
    fun testDestinationBlacklistTrackers() {
        val filter = RelayAclFilter()

        val loopbackV4 = InetAddress.getByName("127.0.0.1")
        val loopbackV6 = InetAddress.getByName("::1")
        val tracker1 = InetAddress.getByName("93.158.213.92")
        val tracker2 = InetAddress.getByName("208.83.20.20")

        assertFalse(filter.isDestinationAllowed(loopbackV4))
        assertFalse(filter.isDestinationAllowed(loopbackV6))
        assertFalse(filter.isDestinationAllowed(tracker1))
        assertFalse(filter.isDestinationAllowed(tracker2))

        val clean1 = InetAddress.getByName("1.1.1.1")
        val clean2 = InetAddress.getByName("142.250.190.46")

        assertTrue(filter.isDestinationAllowed(clean1))
        assertTrue(filter.isDestinationAllowed(clean2))
    }

    @Test
    fun testUdpOverTcpFrameRoundtrip() {
        val sessionId = byteArrayOf(0xAA.toByte(), 0xBB.toByte(), 0xCC.toByte(), 0x11, 0x22, 0x33)
        val streamTag = byteArrayOf(0x55, 0x66)
        val payload = byteArrayOf(0x12, 0x34, 0x01, 0x00, 0x00, 0x01)

        val frame = UdpOverTcpFrame(sessionId, streamTag, payload)
        val encoded = frame.encode()
        assertEquals(8 + payload.size, encoded.size)

        val decoded = UdpOverTcpFrame.decode(encoded)
        assertNotNull(decoded)
        assertArrayEquals(sessionId, decoded!!.sessionId)
        assertArrayEquals(streamTag, decoded.streamTag)
        assertArrayEquals(payload, decoded.payload)

        // Response building and decoding
        val respPayload = byteArrayOf(0x12, 0x34, 0x81.toByte(), 0x80.toByte())
        val respBytes = UdpOverTcpFrame.buildResponse(streamTag, respPayload)
        assertEquals(2 + respPayload.size, respBytes.size)

        val decodedResp = UdpOverTcpFrame.decodeResponse(respBytes)
        assertNotNull(decodedResp)
        assertArrayEquals(streamTag, decodedResp!!.first)
        assertArrayEquals(respPayload, decodedResp.second)

        // Truncated buffer check
        assertNull(UdpOverTcpFrame.decode(byteArrayOf(1, 2, 3)))
        assertNull(UdpOverTcpFrame.decodeResponse(byteArrayOf(1)))

        val key = UdpOverTcpFrame.channelKey("1.1.1.1:53", sessionId, streamTag)
        assertEquals("1.1.1.1:53:aabbcc1122335566", key)
    }
}
