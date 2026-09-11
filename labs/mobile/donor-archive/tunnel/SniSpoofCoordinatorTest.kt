package com.luminet.android.tunnel

import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertNotNull
import org.junit.Assert.assertNull
import org.junit.Assert.assertTrue
import org.junit.Test

class SniSpoofCoordinatorTest {

    @Test
    fun testCloudflareCidrMatching() {
        assertTrue(CloudflareCidrMatcher.isCloudflareIp("104.16.1.1"))
        assertTrue(CloudflareCidrMatcher.isCloudflareIp("104.21.50.2"))
        assertTrue(CloudflareCidrMatcher.isCloudflareIp("172.64.0.100"))
        assertTrue(CloudflareCidrMatcher.isCloudflareIp("188.114.96.20"))

        assertFalse(CloudflareCidrMatcher.isCloudflareIp("8.8.8.8"))
        assertFalse(CloudflareCidrMatcher.isCloudflareIp("192.168.1.1"))
        assertFalse(CloudflareCidrMatcher.isCloudflareIp("invalid.ip"))
    }

    @Test
    fun testSniDomainCleaner() {
        assertEquals("cloudflare.com", SniDomainCleaner.cleanDomain("https://cloudflare.com/path?q=1"))
        assertEquals("speedtest.net", SniDomainCleaner.cleanDomain("  HTTP://SpeedTest.NET:443/ "))
        assertEquals("sub.domain.org", SniDomainCleaner.cleanDomain("sub.domain.org:8443"))

        assertNull(SniDomainCleaner.cleanDomain("# comment line"))
        assertNull(SniDomainCleaner.cleanDomain("   "))
        assertNull(SniDomainCleaner.cleanDomain("singleword"))
    }

    @Test
    fun testTlsClientHelloTemplateBuild() {
        val random = ByteArray(32) { it.toByte() }
        val sessionId = ByteArray(32) { (it + 32).toByte() }
        val keyShare = ByteArray(32) { (it + 64).toByte() }

        val ch1 = TlsClientHelloTemplate.build("speedtest.net", random, sessionId, keyShare)
        assertEquals(517, ch1.size)
        assertEquals(0x16.toByte(), ch1[0]) // Handshake
        assertEquals(0x03.toByte(), ch1[1])
        assertEquals(0x01.toByte(), ch1[2])

        val ch2 = TlsClientHelloTemplate.build("mci.ir", random, sessionId, keyShare)
        assertEquals(517, ch2.size)
    }

    @Test
    fun testOutboundKillSwitchGuard() {
        val guard = OutboundKillSwitchGuard(enabled = true)
        guard.armedSni = true
        guard.armedCore = true

        // Heartbeat when both running -> no block
        assertFalse(guard.onHeartbeat(sniRunning = true, coreRunning = true))
        assertFalse(guard.isBlocked)

        // Core crashes -> triggers block
        assertTrue(guard.onHeartbeat(sniRunning = true, coreRunning = false))
        assertTrue(guard.isBlocked)

        // Subsequent check while down -> no double trigger
        assertFalse(guard.onHeartbeat(sniRunning = true, coreRunning = false))

        // Disarming restores unblock
        guard.disarm(sni = true, core = false)
        assertTrue(guard.disarm(sni = false, core = true))
        assertFalse(guard.isBlocked)
    }
}
