package com.luminet.android.scanner

import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertTrue
import org.junit.Assert.fail
import org.junit.Test

class SocksStageProberTest {

    @Test
    fun testBuildAndVerifyGreeting() {
        val greeting = SocksPacketBuilder.buildGreeting(byteArrayOf(0x00, 0x02))
        assertEquals(4, greeting.size)
        assertEquals(0x05.toByte(), greeting[0])
        assertEquals(0x02.toByte(), greeting[1])
        assertEquals(0x00.toByte(), greeting[2])
        assertEquals(0x02.toByte(), greeting[3])

        // Verify reply
        val okReply = byteArrayOf(0x05, 0x00)
        val authMethod = SocksPacketBuilder.verifyGreetingReply(okReply)
        assertEquals(0x00.toByte(), authMethod)

        val rejectReply = byteArrayOf(0x05, 0xFF.toByte())
        try {
            SocksPacketBuilder.verifyGreetingReply(rejectReply)
            fail("Expected exception for rejected auth")
        } catch (e: IllegalStateException) {
            // Success
        }
    }

    @Test
    fun testBuildAndVerifyConnect() {
        val ipv4Req = SocksPacketBuilder.buildConnectIpv4(byteArrayOf(127, 0, 0, 1), 8080)
        assertEquals(10, ipv4Req.size)
        assertEquals(0x05.toByte(), ipv4Req[0])
        assertEquals(0x01.toByte(), ipv4Req[1])
        assertEquals(0x00.toByte(), ipv4Req[2])
        assertEquals(0x01.toByte(), ipv4Req[3])

        val domainReq = SocksPacketBuilder.buildConnectDomain("example.com", 443)
        assertEquals(4 + 1 + 11 + 2, domainReq.size)
        assertEquals(0x03.toByte(), domainReq[3])
        assertEquals(11.toByte(), domainReq[4])

        // Verify replies
        val okReply = byteArrayOf(0x05, 0x00, 0x00, 0x01)
        SocksPacketBuilder.verifyConnectReply(okReply)

        val errReply = byteArrayOf(0x05, 0x05, 0x00, 0x01)
        try {
            SocksPacketBuilder.verifyConnectReply(errReply)
            fail("Expected exception for connection refused")
        } catch (e: IllegalStateException) {
            assertTrue(e.message?.contains("connection refused") == true)
        }
    }

    @Test
    fun testParseTraceBody() {
        val body = """
            fl=42f10
            h=connectivity.cloudflareclient.com
            ip=1.2.3.4
            ts=1713988096
            visit_scheme=http
            uag=Oblivion
            colo=FRA
            sliver=none
            http=http/1.1
            loc=DE
            tls=off
            sni=plaintext
            warp=on
        """.trimIndent()

        val parsed = SocksPacketBuilder.parseTraceBody(body)
        assertEquals("FRA", parsed.colo)
        assertEquals("DE", parsed.loc)
        assertEquals("1.2.3.4", parsed.ip)
        assertEquals("on", parsed.warp)
        assertEquals("http", parsed.visitScheme)
        assertTrue(parsed.isWarpOk)
    }

    @Test
    fun testAttemptLadder() {
        assertEquals(105L, AttemptLadder.calculateValidationBudget("turbo"))
        assertEquals(360L, AttemptLadder.calculateValidationBudget("thorough"))
        assertEquals(240L, AttemptLadder.calculateValidationBudget("stealth"))
        assertEquals(180L, AttemptLadder.calculateValidationBudget("standard"))

        val stages = AttemptLadder.buildAttempts("standard", "127.0.0.1:8086", fastFirstConnect = true, isPsiphon = false)
        assertEquals(2, stages.size)
        assertEquals("fast", stages[0].label)
        assertEquals(30L, stages[0].budgetSec)
        assertEquals("configured", stages[1].label)
        assertEquals(180L, stages[1].budgetSec)

        val psiphonStages = AttemptLadder.buildAttempts("standard", "127.0.0.1:8086", fastFirstConnect = true, isPsiphon = true)
        assertEquals(1, psiphonStages.size)
        assertEquals("configured", psiphonStages[0].label)
    }
}
