package com.luminet.android.tunnel

import org.junit.Assert.*
import org.junit.Test

class ServerlessDirectShaperTest {

    @Test
    fun testIsCensorshipSink() {
        assertTrue(ServerlessDirectShaper.isCensorshipSink("10.10.34.1"))
        assertTrue(ServerlessDirectShaper.isCensorshipSink("10.10.34.254"))
        assertFalse(ServerlessDirectShaper.isCensorshipSink("1.1.1.1"))

        assertTrue(ServerlessDirectShaper.isCensorshipSink("2001:4188:2:600::1"))
        assertTrue(ServerlessDirectShaper.isCensorshipSink("2001:4188:0002:0600::beef"))
        assertFalse(ServerlessDirectShaper.isCensorshipSink("2606:4700:4700::1111"))
    }

    @Test
    fun testShapeClientHelloLowDelay() {
        val payload = ByteArray(100) { (it % 256).toByte() }
        val config = ServerlessDirectShaper.ServerlessShaperConfig(
            profile = ServerlessDirectShaper.ServerlessProfile.LOW_DELAY,
            tlsRecordSplit = 5,
            sniSplitOffset = 43
        )

        val fragments = ServerlessDirectShaper.shapeClientHello(payload, config)
        assertTrue(fragments.size >= 3)
        assertEquals(5, fragments[0].payload.size)
        assertEquals(0L, fragments[0].delayMs)
        assertEquals(38, fragments[1].payload.size)

        val reconstructed = ServerlessDirectShaper.reconstruct(fragments)
        assertArrayEquals(payload, reconstructed)
    }

    @Test
    fun testShapeClientHelloHighDelay() {
        val payload = ByteArray(80) { (it % 256).toByte() }
        val config = ServerlessDirectShaper.ServerlessShaperConfig(
            profile = ServerlessDirectShaper.ServerlessProfile.HIGH_DELAY,
            tlsRecordSplit = 5,
            sniSplitOffset = 43
        )

        val fragments = ServerlessDirectShaper.shapeClientHello(payload, config)
        val hasStall = fragments.any { it.delayMs == 400L }
        assertTrue("High delay profile should include rhythmic 400ms stalls", hasStall)

        val reconstructed = ServerlessDirectShaper.reconstruct(fragments)
        assertArrayEquals(payload, reconstructed)
    }

    @Test
    fun testShapeTcpStream() {
        val data = "GET / HTTP/1.1\r\nHost: example.org\r\n\r\n".toByteArray()
        val fragments = ServerlessDirectShaper.shapeTcpStream(data)
        assertEquals(data.size, fragments.size)

        val reconstructed = ServerlessDirectShaper.reconstruct(fragments)
        assertArrayEquals(data, reconstructed)
    }

    @Test
    fun testGenerateUdpNoise() {
        val config = ServerlessDirectShaper.ServerlessShaperConfig(
            udpNoiseEnabled = true,
            udpNoiseMinLen = 1200,
            udpNoiseMaxLen = 1230
        )

        val noise = ServerlessDirectShaper.generateUdpNoise(10L, config)
        assertNotNull(noise)
        assertTrue(noise!!.size in 1200..1230)

        val disabledConfig = config.copy(udpNoiseEnabled = false)
        assertNull(ServerlessDirectShaper.generateUdpNoise(10L, disabledConfig))
    }
}
