package com.luminet.android.tunnel

import org.junit.Assert.*
import org.junit.Test

class RelayResponseClassifierTest {

    @Test
    fun testClassifyRelayError() {
        val quotaMsg = RelayResponseClassifier.classifyRelayError("Service invoked too many times: urlfetch")
        assertTrue(quotaMsg.contains("quota exhausted"))

        val authMsg = RelayResponseClassifier.classifyRelayError("Exception: Authorization is required to perform that action.")
        assertTrue(authMsg.contains("auth/permission error"))

        val loopMsg = RelayResponseClassifier.classifyRelayError("loop_detected")
        assertTrue(loopMsg.contains("loop detected"))

        assertEquals(PermanentFailureCategory.QUOTA, RelayResponseClassifier.classifyPermanentFailure("Bandwidth quota exceeded"))
        assertEquals(PermanentFailureCategory.AUTH, RelayResponseClassifier.classifyPermanentFailure("Permission denied"))
        assertEquals(PermanentFailureCategory.DEPLOY, RelayResponseClassifier.classifyPermanentFailure("Deployment not found"))
        assertEquals(PermanentFailureCategory.ADMIN, RelayResponseClassifier.classifyPermanentFailure("Disabled by administrator"))
        assertNull(RelayResponseClassifier.classifyPermanentFailure("Server not available"))
    }

    @Test
    fun testSplitSetCookie() {
        val blob = "session=abc123; Expires=Wed, 21 Oct 2026 07:28:00 GMT; Path=/, token=def456; Secure"
        val cookies = RelayResponseClassifier.splitSetCookie(blob)
        assertEquals(2, cookies.size)
        assertEquals("session=abc123; Expires=Wed, 21 Oct 2026 07:28:00 GMT; Path=/", cookies[0])
        assertEquals("token=def456; Secure", cookies[1])
    }

    @Test
    fun testIsSafeTargetUrl() {
        assertTrue(RelayResponseClassifier.isSafeTargetUrl("https://example.com/api"))
        assertTrue(RelayResponseClassifier.isSafeTargetUrl("http://93.184.216.34:80/"))
        assertFalse(RelayResponseClassifier.isSafeTargetUrl("http://localhost:8080/"))
        assertFalse(RelayResponseClassifier.isSafeTargetUrl("http://myhost.local/"))
        assertFalse(RelayResponseClassifier.isSafeTargetUrl("ftp://example.com/"))
    }

    @Test
    fun testCheckRelayLoop() {
        assertNotNull(RelayResponseClassifier.checkRelayLoop("https://exit.com/api", "exit.com:443", false))
        assertNotNull(RelayResponseClassifier.checkRelayLoop("https://script.google.com/macros/s/xyz/exec", "myexit.com", true))
        assertNull(RelayResponseClassifier.checkRelayLoop("https://target.com/path", "exit.com:443", false))
    }

    @Test
    fun testAdblockHostsParser() {
        val hosts = """
            # Adblock test
            0.0.0.0 ads.example.com # inline comment
            127.0.0.1 tracker.analytics.org
            direct-bad.com
            *.wildcard.com
            localhost
            192.168.1.1
            0.0.0.0 ads.example.com # duplicate
        """.trimIndent()

        val parsed = AdblockHostsParser.parseHostsText(hosts)
        assertEquals(3, parsed.size)
        assertTrue(parsed.contains("ads.example.com"))
        assertTrue(parsed.contains("tracker.analytics.org"))
        assertTrue(parsed.contains("direct-bad.com"))
    }
}
