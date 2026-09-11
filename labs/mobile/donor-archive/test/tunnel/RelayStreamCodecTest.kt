package com.luminet.android.tunnel

import org.junit.Assert.*
import org.junit.Test

class RelayStreamCodecTest {

    @Test
    fun testV1TcpRoundTrip() {
        val header = RelayStreamHeader(RelayNetwork.TCP, "1.1.1.1", 443)
        val encoded = header.encodeV1()
        val expected = "tcp@1.1.1.1$443\r".toByteArray(Charsets.UTF_8)
        assertArrayEquals(expected, encoded)

        val (decoded, consumed) = RelayStreamHeader.decodeV1(encoded)
        assertEquals(encoded.size, consumed)
        assertEquals(RelayNetwork.TCP, decoded.network)
        assertEquals("1.1.1.1", decoded.host)
        assertEquals(443, decoded.port)
    }

    @Test
    fun testV1UdpRoundTrip() {
        val header = RelayStreamHeader(RelayNetwork.UDP, "dns.google", 53)
        val encoded = header.encodeV1()
        val (decoded, consumed) = RelayStreamHeader.decodeV1(encoded)
        assertEquals(encoded.size, consumed)
        assertEquals(RelayNetwork.UDP, decoded.network)
        assertEquals("dns.google", decoded.host)
        assertEquals(53, decoded.port)
    }

    @Test
    fun testV2BinaryRoundTrip() {
        val header = RelayStreamHeader(RelayNetwork.TCP, "proxy.edge.internal", 8443)
        val encoded = header.encodeV2()
        assertEquals('R'.code.toByte(), encoded[0])
        assertEquals('2'.code.toByte(), encoded[1])

        val (decoded, consumed) = RelayStreamHeader.decodeV2(encoded)
        assertEquals(encoded.size, consumed)
        assertEquals(RelayNetwork.TCP, decoded.network)
        assertEquals("proxy.edge.internal", decoded.host)
        assertEquals(8443, decoded.port)
    }
}
