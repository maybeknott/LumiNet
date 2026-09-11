package com.luminet.android.scanner

import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertTrue
import org.junit.Test
import java.nio.ByteBuffer
import java.nio.ByteOrder

class WarpEndpointScannerTest {

    @Test
    fun testWarpPortsAndCandidates() {
        assertEquals(54, WarpEndpointScanner.WARP_PORTS.size)
        assertTrue(WarpEndpointScanner.WARP_PORTS.contains(500))
        assertTrue(WarpEndpointScanner.WARP_PORTS.contains(8886))

        val candidates = WarpEndpointScanner.generateCandidates(10, false)
        assertEquals(10, candidates.size)
        for (c in candidates) {
            assertTrue(c.contains(":"))
        }
    }

    @Test
    fun testBuildInitiationPacket() {
        val pkt = WarpEndpointScanner.buildInitiationPacket(42)
        assertEquals(WarpEndpointScanner.INITIATION_PACKET_LEN, pkt.size)

        val buf = ByteBuffer.wrap(pkt).order(ByteOrder.LITTLE_ENDIAN)
        assertEquals(1, buf.getInt(0)) // Type 1
        assertEquals(42, buf.getInt(4)) // Sender index
    }

    @Test
    fun testValidateResponse() {
        val resp = ByteArray(WarpEndpointScanner.RESPONSE_PACKET_LEN)
        val buf = ByteBuffer.wrap(resp).order(ByteOrder.LITTLE_ENDIAN)
        buf.putInt(0, 2) // Type 2 (Response)
        buf.putInt(4, 999) // Peer sender index
        buf.putInt(8, 42) // Receiver index (matches our 42)

        assertTrue(WarpEndpointScanner.validateResponse(resp, 42))
        assertFalse(WarpEndpointScanner.validateResponse(resp, 99)) // mismatch receiver
    }

    @Test
    fun testRankEndpoints() {
        val r1 = WarpEndpointScanner.WarpScanResult("1.1.1.1:500", 50.0, 5.0, 0.0, 3, 3)
        val r2 = WarpEndpointScanner.WarpScanResult("1.1.1.2:500", 30.0, 2.0, 33.3, 3, 2) // faster but has packet loss
        val r3 = WarpEndpointScanner.WarpScanResult("1.1.1.3:500", 40.0, 2.0, 0.0, 3, 3) // 0% loss, lower RTT than r1

        val ranked = WarpEndpointScanner.rankEndpoints(listOf(r1, r2, r3))
        // 0% loss comes first, with r3 having lower RTT/jitter than r1
        assertEquals("1.1.1.3:500", ranked[0].endpoint)
        assertEquals("1.1.1.1:500", ranked[1].endpoint)
        assertEquals("1.1.1.2:500", ranked[2].endpoint)
    }
}
