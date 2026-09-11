package com.luminet.android.scanner

import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertNotNull
import org.junit.Assert.assertTrue
import org.junit.Test

class CheckHostProberTest {

    @Test
    fun testBuildInitiateUrl() {
        val url = CheckHostProber.buildInitiateUrl("1.1.1.1", CheckHostProber.ProbeMethod.PING)
        assertTrue(url.startsWith("https://check-host.net/check-ping?host=1.1.1.1"))
        for (node in CheckHostProber.DEFAULT_IRAN_NODES) {
            assertTrue(url.contains("&node=$node"))
        }

        val httpUrl = CheckHostProber.buildInitiateUrl("example.com", CheckHostProber.ProbeMethod.HTTP)
        assertTrue(httpUrl.startsWith("https://check-host.net/check-http?host=example.com"))

        val resultUrl = CheckHostProber.buildResultUrl("req-abc-999")
        assertEquals("https://check-host.net/check-result/req-abc-999", resultUrl)
    }

    @Test
    fun testParseInitiateResponse() {
        val okJson = """{"ok": 1, "request_id": "req-xyz-123"}"""
        val reqId = CheckHostProber.parseInitiateResponse(okJson)
        assertEquals("req-xyz-123", reqId)
    }

    @Test
    fun testParsePingResults() {
        val pingJson = """{
            "ir1.node.check-host.net": [[
                ["OK", 0.045],
                ["OK", 0.043]
            ]],
            "ir2.node.check-host.net": [[
                ["OK", 0.050]
            ]],
            "ir3.node.check-host.net": [[
                ["TIMEOUT", 0.0]
            ]]
        }"""

        val assessment = CheckHostProber.parseResultResponse(
            pingJson,
            "8.8.8.8",
            CheckHostProber.ProbeMethod.PING
        )
        assertEquals(3, assessment.totalNodes)
        assertEquals(2, assessment.responsiveNodes)
        assertEquals(1, assessment.blockedNodes)
        assertNotNull(assessment.avgRttMs)
        assertTrue(assessment.isReady)
    }

    @Test
    fun testParseHttpBlocked() {
        val blockedJson = """{
            "ir1.node.check-host.net": [[0, 5.0, "Connection timed out", null, null]],
            "ir2.node.check-host.net": [[0, 5.0, "Connection timed out", null, null]],
            "ir3.node.check-host.net": [[0, 2.5, "Connection reset by peer", null, null]]
        }"""

        val assessment = CheckHostProber.parseResultResponse(
            blockedJson,
            "blocked.example.com",
            CheckHostProber.ProbeMethod.HTTP
        )
        assertEquals(0, assessment.responsiveNodes)
        assertEquals(3, assessment.blockedNodes)
        assertEquals(CheckHostProber.CensorshipVerdict.FILTERED, assessment.verdict)
    }

    @Test
    fun testParseDnsResults() {
        val dnsJson = """{
            "ir1.node.check-host.net": [{"A": ["93.184.216.34"], "TTL": 300}],
            "ir2.node.check-host.net": [{"A": ["10.10.34.34"], "TTL": 60}]
        }"""

        val assessment = CheckHostProber.parseResultResponse(
            dnsJson,
            "example.com",
            CheckHostProber.ProbeMethod.DNS
        )
        assertEquals(2, assessment.responsiveNodes)
        assertEquals(0, assessment.blockedNodes)
        assertEquals(CheckHostProber.CensorshipVerdict.CLEAN, assessment.verdict)
    }
}
