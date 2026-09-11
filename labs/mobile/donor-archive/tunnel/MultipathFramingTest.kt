package com.luminet.android.tunnel

import org.junit.Assert.assertArrayEquals
import org.junit.Assert.assertEquals
import org.junit.Test

class MultipathFramingTest {

    @Test
    fun testFrameEncodeDecode() {
        val sid = ByteArray(16) { it.toByte() }
        val payload = "echo.route.internal:8080".toByteArray(Charsets.UTF_8)
        val frame = MpFrame(MpFrameType.HELLO, sid, 100L, payload)

        val encoded = frame.encode()
        assertEquals(29 + payload.size, encoded.size)

        val decoded = MpFrame.decode(encoded)
        assertEquals(MpFrameType.HELLO, decoded.type)
        assertArrayEquals(sid, decoded.sessionId)
        assertEquals(100L, decoded.seq)
        assertArrayEquals(payload, decoded.payload)
    }

    @Test
    fun testDedupBufferReordering() {
        val buf = InOrderDedupBuffer(startSeq = 0L, capacity = 10)

        assertEquals(0, buf.push(2L, "f2".toByteArray()).size)
        assertEquals(0, buf.push(1L, "f1".toByteArray()).size)

        val delivered = buf.push(0L, "f0".toByteArray())
        assertEquals(3, delivered.size)
        assertEquals("f0", String(delivered[0]))
        assertEquals("f1", String(delivered[1]))
        assertEquals("f2", String(delivered[2]))
        assertEquals(3L, buf.nextSeq())
    }
}
