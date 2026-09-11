package com.luminet.android.tunnel

import org.junit.Assert.*
import org.junit.Test

class WebRtcDataChannelCodecTest {

    @Test
    fun testBinaryFrameRoundTrip() {
        val payload = "webrtc datachannel payload content".toByteArray(Charsets.UTF_8)
        val frame = WebRtcDataChannelFrame.binary(payload)
        assertEquals(WebRtcDataChannelConstants.PPID_BINARY, frame.ppid)

        val encoded = frame.encode()
        assertEquals(4 + payload.size, encoded.size)

        val decoded = WebRtcDataChannelFrame.decode(encoded)
        assertEquals(WebRtcDataChannelConstants.PPID_BINARY, decoded.ppid)
        assertArrayEquals(payload, decoded.payload)
    }

    @Test
    fun testEmptyFrame() {
        val frame = WebRtcDataChannelFrame.binary(ByteArray(0))
        assertEquals(WebRtcDataChannelConstants.PPID_BINARY_EMPTY, frame.ppid)

        val encoded = frame.encode()
        val decoded = WebRtcDataChannelFrame.decode(encoded)
        assertEquals(WebRtcDataChannelConstants.PPID_BINARY_EMPTY, decoded.ppid)
        assertEquals(0, decoded.payload.size)
    }

    @Test
    fun testStringFrameRoundTrip() {
        val text = "hello from webrtc string frame"
        val frame = WebRtcDataChannelFrame.string(text)
        assertEquals(WebRtcDataChannelConstants.PPID_STRING, frame.ppid)

        val encoded = frame.encode()
        val decoded = WebRtcDataChannelFrame.decode(encoded)
        assertEquals(WebRtcDataChannelConstants.PPID_STRING, decoded.ppid)
        assertEquals(text, String(decoded.payload, Charsets.UTF_8))
    }
}
