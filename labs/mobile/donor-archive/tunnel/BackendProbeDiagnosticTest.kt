package com.luminet.android.tunnel

import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertNotNull
import org.junit.Assert.assertNull
import org.junit.Assert.assertTrue
import org.junit.Test

class BackendProbeDiagnosticTest {

    private val diagnostic = BackendProbeDiagnostic()

    @Test
    fun testFormatWsHandshake() {
        val (req, targetTried, host) = diagnostic.formatWsHandshake("https://node.example.org:8443", "/my-path")
        assertEquals("https://node.example.org:8443/my-path", targetTried)
        assertEquals("node.example.org", host)
        assertTrue(req.startsWith("GET /my-path HTTP/1.1\r\n"))
        assertTrue(req.contains("Upgrade: websocket\r\n"))
    }

    @Test
    fun testEvaluateResponseSuccess() {
        val (steps, hint) = diagnostic.evaluateResponse(101, "nginx", "node.example.org", 65, true)
        assertTrue(steps[0].contains("SUCCESS"))
        assertNull(hint)
    }

    @Test
    fun testEvaluateResponseRawIp403() {
        val (steps, hint) = diagnostic.evaluateResponse(403, "cloudflare", "198.51.100.1", 35, false)
        assertTrue(steps[0].contains("Edge SSRF sandbox blocks bare IP"))
        assertNotNull(hint)
        assertTrue(hint!!.contains("DNS-only"))
    }

    @Test
    fun testDuplexTrafficMeter() {
        val meter = DuplexTrafficMeter("client-42")
        meter.recordUp(2048)
        meter.recordDown(8192)
        assertEquals(2048, meter.getUpBytes())
        assertEquals(8192, meter.getDownBytes())
        assertEquals(10240, meter.totalBytes())
    }
}
