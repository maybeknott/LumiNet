package com.luminet.android.tunnel

import org.junit.Assert.assertArrayEquals
import org.junit.Assert.assertEquals
import org.junit.Assert.assertNotNull
import org.junit.Assert.assertNull
import org.junit.Assert.assertTrue
import org.junit.Test
import java.nio.ByteBuffer

class SniFragmenterTest {

    private fun buildTestClientHello(sni: String): ByteArray {
        val sniBytes = sni.toByteArray(Charsets.UTF_8)

        // SNI extension
        val extSni = ByteBuffer.allocate(9 + sniBytes.size)
        extSni.putShort(0x0000.toShort()) // Type
        extSni.putShort((5 + sniBytes.size).toShort()) // Extension length
        extSni.putShort((3 + sniBytes.size).toShort()) // Server name list length
        extSni.put(0x00.toByte()) // Hostname type
        extSni.putShort(sniBytes.size.toShort())
        extSni.put(sniBytes)

        val sniExtBytes = extSni.array()

        // ALPN extension
        val alpnExtBytes = byteArrayOf(0x00, 0x10, 0x00, 0x03, 0x02, 'h'.code.toByte(), '2'.code.toByte())
        val extensions = sniExtBytes + alpnExtBytes

        // Handshake body
        val bodyBuf = ByteBuffer.allocate(2 + 32 + 1 + 4 + 2 + 2 + extensions.size)
        bodyBuf.putShort(0x0303.toShort()) // TLS 1.2
        bodyBuf.put(ByteArray(32)) // Random
        bodyBuf.put(0x00.toByte()) // Session ID length 0
        bodyBuf.putShort(2.toShort()) // Cipher suites len
        bodyBuf.putShort(0x1301.toShort()) // TLS_AES_128_GCM_SHA256
        bodyBuf.put(1.toByte()) // Compression len
        bodyBuf.put(0.toByte()) // Compression null
        bodyBuf.putShort(extensions.size.toShort())
        bodyBuf.put(extensions)

        val body = bodyBuf.array()

        // Handshake header
        val handshakeBuf = ByteBuffer.allocate(4 + body.size)
        handshakeBuf.put(0x01.toByte()) // ClientHello
        handshakeBuf.put((body.size shr 16).toByte())
        handshakeBuf.put((body.size shr 8).toByte())
        handshakeBuf.put((body.size and 0xFF).toByte())
        handshakeBuf.put(body)

        val handshake = handshakeBuf.array()

        // Record header
        val recordBuf = ByteBuffer.allocate(5 + handshake.size)
        recordBuf.put(0x16.toByte()) // Handshake
        recordBuf.putShort(0x0301.toShort()) // TLS 1.0
        recordBuf.putShort(handshake.size.toShort())
        recordBuf.put(handshake)

        return recordBuf.array()
    }

    @Test
    fun testSniExtractionAndLocation() {
        val packet = buildTestClientHello("cloudflare.com")
        val fragmenter = SniFragmenter()

        val sni = fragmenter.extractSni(packet)
        assertEquals("cloudflare.com", sni)

        val location = fragmenter.locateSni(packet)
        assertNotNull(location)
        val (start, end, name) = location!!
        assertEquals("cloudflare.com", name)
        assertEquals("cloudflare.com", String(packet.copyOfRange(start, end), Charsets.UTF_8))
    }

    @Test
    fun testPlanFragmentsTotalBytesAndContinuity() {
        val packet = buildTestClientHello("api.github.com")
        val fragmenter = SniFragmenter()
        val cfg = SniFragmentConfig()

        val plan = fragmenter.planFragments(packet, cfg)
        assertEquals("api.github.com", plan.detectedSni)
        assertEquals(packet.size, plan.totalBytes)

        var hasBefore = false
        var hasSni = false
        var hasAfter = false

        val reconstructed = mutableListOf<Byte>()
        for (slice in plan.slices) {
            for (b in slice.payload) {
                reconstructed.add(b)
            }
            when (slice.zone) {
                "before_sni" -> hasBefore = true
                "sni" -> hasSni = true
                "after_sni" -> hasAfter = true
            }
        }

        assertTrue(hasBefore)
        assertTrue(hasSni)
        assertTrue(hasAfter)
        assertArrayEquals(packet, reconstructed.toByteArray())
    }

    @Test
    fun testPassthroughNonTls() {
        val rawHttp = "GET / HTTP/1.1\r\nHost: example.com\r\n\r\n".toByteArray(Charsets.UTF_8)
        val fragmenter = SniFragmenter()
        val plan = fragmenter.planFragments(rawHttp)

        assertNull(plan.detectedSni)
        assertEquals(1, plan.slices.size)
        assertEquals("passthrough", plan.slices[0].zone)
        assertArrayEquals(rawHttp, plan.slices[0].payload)
    }
}
