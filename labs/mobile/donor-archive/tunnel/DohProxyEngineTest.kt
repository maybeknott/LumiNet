package com.luminet.android.tunnel

import org.junit.Assert.*
import org.junit.Test
import java.nio.ByteBuffer

class DohProxyEngineTest {

    @Test
    fun testValidateDohResponse() {
        val valid = byteArrayOf(
            0x12, 0x34,
            0x81.toByte(), 0x80.toByte(),
            0x00, 0x01,
            0x00, 0x01,
            0x00, 0x00,
            0x00, 0x00
        )
        assertTrue(DohProxyEngine.validateDohResponse(valid))

        val query = byteArrayOf(
            0x12, 0x34,
            0x01, 0x00,
            0x00, 0x01,
            0x00, 0x00,
            0x00, 0x00,
            0x00, 0x00
        )
        assertFalse(DohProxyEngine.validateDohResponse(query))
        assertFalse(DohProxyEngine.validateDohResponse(byteArrayOf(0x01, 0x02)))
    }

    @Test
    fun testSplitClientHelloStrategies() {
        val payload = "12345678901234567890123456789012345678901234567890".toByteArray()

        val half = DohProxyEngine.splitClientHello(payload, "half")
        assertEquals(2, half.size)
        assertArrayEquals(payload, DohProxyEngine.reconstruct(half))

        val multi = DohProxyEngine.splitClientHello(payload, "multi")
        assertEquals(3, multi.size)
        assertArrayEquals(payload, DohProxyEngine.reconstruct(multi))
    }
}
