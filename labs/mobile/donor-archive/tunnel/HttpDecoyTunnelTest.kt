// Copyright 2024-2026 LumiNet Authors. All Rights Reserved.
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

package com.luminet.android.tunnel

import org.junit.Assert.assertArrayEquals
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertTrue
import org.junit.Test
import java.nio.charset.StandardCharsets

class HttpDecoyTunnelTest {

    @Test
    fun testAesCbcEnvelopeRoundtrip() {
        val key = ByteArray(32) { 0x33.toByte() }
        val message = "GET /status HTTP/1.1\r\nHost: target.internal\r\n\r\n".toByteArray(StandardCharsets.UTF_8)

        val encrypted = DecoyEnvelope.encrypt(message, key)
        assertTrue(encrypted.size >= 32)

        val decrypted = DecoyEnvelope.decrypt(encrypted, key)
        assertArrayEquals(message, decrypted)
    }

    @Test
    fun testHexTransforms() {
        val original = byteArrayOf(0x00, 0x12, 0x34, 0xAB.toByte(), 0xCD.toByte(), 0xEF.toByte())
        val hex = DecoyEnvelope.toHex(original)
        assertEquals("001234abcdef", hex.lowercase())

        val recovered = DecoyEnvelope.fromHex(hex)
        assertArrayEquals(original, recovered)
    }

    @Test
    fun testAgentServerCodecRoundtrip() {
        val config = DecoyTunnelConfig()
        val codec = DecoyHttpCodec(config)

        val sessionId = "android-sess-100"
        val payload = "CONNECT example.org:443 HTTP/1.1\r\nHost: example.org\r\n\r\n".toByteArray(StandardCharsets.UTF_8)

        // 1. Agent encodes request
        val wireReq = codec.encodeAgentRequest(sessionId, DecoyAction.OPEN, payload, seed = 1)
        val wireStr = String(wireReq, StandardCharsets.UTF_8)
        assertTrue(wireStr.contains("X-Nipo-Session: $sessionId"))
        assertTrue(wireStr.contains("X-Nipo-Action: open"))

        // 2. Server decodes request
        val (parsedReq, decryptedPayload) = codec.decodeServerRequest(wireReq)
        assertEquals(sessionId, parsedReq.sessionId)
        assertEquals(DecoyAction.OPEN, parsedReq.action)
        assertArrayEquals(payload, decryptedPayload)

        // 3. Server encodes response
        val responsePayload = "HTTP/1.1 200 Connection Established\r\n\r\n".toByteArray(StandardCharsets.UTF_8)
        val wireResp = codec.encodeServerResponse(200, "Connection Established", responsePayload, keepAlive = true)

        // 4. Agent decodes response
        val (parsedResp, decryptedResp) = codec.decodeAgentResponse(wireResp)
        assertEquals(200, parsedResp.statusCode)
        assertTrue(parsedResp.keepAlive)
        assertArrayEquals(responsePayload, decryptedResp)
    }

    @Test
    fun testDecoyActionParsing() {
        assertEquals(DecoyAction.OPEN, DecoyAction.fromWire("open"))
        assertEquals(DecoyAction.REQUEST, DecoyAction.fromWire("request"))
        assertEquals(DecoyAction.SEND, DecoyAction.fromWire("send"))
        assertEquals(DecoyAction.RECV, DecoyAction.fromWire("recv"))
        assertEquals(DecoyAction.CLOSE, DecoyAction.fromWire("close"))
        assertEquals(DecoyAction.OPEN, DecoyAction.fromWire("unknown_action"))
    }

    @Test
    fun testSessionTracker() {
        val tracker = DecoySessionTracker("tracker-1")
        assertFalse(tracker.isConnected)

        tracker.markConnected()
        assertTrue(tracker.isConnected)
        assertEquals(DecoyAction.SEND, tracker.activeAction)

        tracker.recordSent(256)
        tracker.recordReceived(512)
        assertEquals(256L, tracker.bytesSent)
        assertEquals(512L, tracker.bytesReceived)

        tracker.markClosed()
        assertFalse(tracker.isConnected)
        assertEquals(DecoyAction.CLOSE, tracker.activeAction)
    }
}
