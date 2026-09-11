package com.luminet.android.tunnel

import org.junit.Assert.*
import org.junit.Test

class DnsPoisonDetectorTest {

    @Test
    fun testIsPoisonedIPv4() {
        // Iranian National Filtering redirect page
        assertTrue(DnsPoisonDetector.isPoisonedIPv4("10.10.34.1").isPoisoned)
        assertTrue(DnsPoisonDetector.isPoisonedIPv4("10.10.34.254").isPoisoned)

        // RFC 1918 Class A
        assertTrue(DnsPoisonDetector.isPoisonedIPv4("10.0.0.1").isPoisoned)

        // Loopback
        assertTrue(DnsPoisonDetector.isPoisonedIPv4("127.0.0.1").isPoisoned)

        // RFC 1918 Class C
        assertTrue(DnsPoisonDetector.isPoisonedIPv4("192.168.1.1").isPoisoned)

        // RFC 1918 Class B
        assertTrue(DnsPoisonDetector.isPoisonedIPv4("172.16.0.1").isPoisoned)
        assertTrue(DnsPoisonDetector.isPoisonedIPv4("172.31.255.254").isPoisoned)
        assertFalse(DnsPoisonDetector.isPoisonedIPv4("172.32.0.1").isPoisoned)

        // CGNAT
        assertTrue(DnsPoisonDetector.isPoisonedIPv4("100.64.0.1").isPoisoned)
        assertTrue(DnsPoisonDetector.isPoisonedIPv4("100.127.255.254").isPoisoned)
        assertFalse(DnsPoisonDetector.isPoisonedIPv4("100.128.0.1").isPoisoned)

        // Clean IPs
        assertFalse(DnsPoisonDetector.isPoisonedIPv4("8.8.8.8").isPoisoned)
        assertFalse(DnsPoisonDetector.isPoisonedIPv4("1.1.1.1").isPoisoned)
        assertFalse(DnsPoisonDetector.isPoisonedIPv4("142.250.190.46").isPoisoned)
    }

    @Test
    fun testDnsVault() {
        val vault = DnsPoisonDetector.DnsVault()

        vault.updateRecord("1.1.1.1", 30, true, "Cloudflare")
        vault.updateRecord("8.8.8.8", 15, true, "Google")
        vault.updateRecord("10.10.34.1", 2, false, "Poisoned")

        val clean = vault.rankCleanResolvers()
        assertEquals(2, clean.size)
        assertEquals("8.8.8.8", clean[0].ip)
        assertEquals("1.1.1.1", clean[1].ip)

        val fastest = vault.getFastestClean()
        assertNotNull(fastest)
        assertEquals("8.8.8.8", fastest?.ip)
    }
}
