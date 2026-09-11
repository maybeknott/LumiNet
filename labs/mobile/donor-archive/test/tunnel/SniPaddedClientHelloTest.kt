package com.luminet.android.tunnel

import org.junit.Assert.*
import org.junit.Test
import java.nio.ByteBuffer
import java.nio.ByteOrder

class SniPaddedClientHelloTest {

    @Test
    fun testPaddedClientHelloExact517Bytes() {
        val testDomains = listOf(
            "a.co",
            "example.com",
            "gateway.target-edge.infra.org",
            "very-long-domain-name-testing-padding-calculation-safety.node.internal.io"
        )

        for (domain in testDomains) {
            val packet = SniPaddedClientHello.buildPaddedClientHello(domain)
            assertEquals(517, packet.size)

            val bb = ByteBuffer.wrap(packet).order(ByteOrder.BIG_ENDIAN)
            assertEquals(0x16.toByte(), bb.get()) // Handshake record
            assertEquals(0x0301.toShort(), bb.short) // TLS 1.0 record ver
            assertEquals(512.toShort(), bb.short) // Length 517 - 5 = 512
            assertEquals(0x01.toByte(), bb.get()) // ClientHello handshake
        }
    }

    @Test(expected = IllegalArgumentException::class)
    fun testEmptySniFails() {
        SniPaddedClientHello.buildPaddedClientHello("")
    }

    @Test(expected = IllegalArgumentException::class)
    fun testOverlongSniFails() {
        val huge = "a".repeat(220) + ".com"
        SniPaddedClientHello.buildPaddedClientHello(huge)
    }
}
