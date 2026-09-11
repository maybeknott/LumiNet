package com.luminet.android.tunnel

import org.junit.Assert.*
import org.junit.Test

class LanShareCoordinatorTest {

    @Test
    fun testSplitSections() {
        val raw = """
            # Global Comment
            [block]
            adserver.example
            malware.bad

            [custom_unknown]
            ignored.domain

            [direct]
            corp.internal
            192.168.0.0/16
        """.trimIndent()

        val (block, direct) = LanShareCoordinator.splitSections(raw)
        assertTrue(block.contains("adserver.example\n"))
        assertTrue(block.contains("malware.bad\n"))
        assertFalse(block.contains("ignored.domain"))
        assertFalse(direct.contains("ignored.domain"))
        assertTrue(direct.contains("corp.internal\n"))
        assertTrue(direct.contains("192.168.0.0/16\n"))
    }

    @Test
    fun testNormalizeMihomoDomains() {
        val input = """
            +.domain1.com
            +.sub.domain2.ir
            normal.org
        """.trimIndent()

        val normalized = LanShareCoordinator.normalizeMihomoDomains(input)
        assertEquals(listOf("domain1.com", "sub.domain2.ir", "normal.org"), normalized)
    }

    @Test
    fun testCompileCombinedRuleset() {
        val user = "[block]\ntracker.net\n[direct]\nlan.local\n"
        val bundledDomains = "+.bank.ir\n"
        val bundledIps = "10.0.0.0/8"

        val combined = LanShareCoordinator.compileCombinedRuleset(user, bundledDomains, bundledIps)
        assertTrue(combined.contains("[block]\ntracker.net"))
        assertTrue(combined.contains("[direct]"))
        assertTrue(combined.contains("bank.ir"))
        assertTrue(combined.contains("10.0.0.0/8"))
        assertTrue(combined.contains("lan.local"))
    }

    @Test
    fun testUnusableBehindTunnel() {
        assertNull(LanShareCoordinator.unusableBehindTunnel("vless", false))
        assertNull(LanShareCoordinator.unusableBehindTunnel("trojan", false))
        assertNotNull(LanShareCoordinator.unusableBehindTunnel("hysteria2", false))
        assertNotNull(LanShareCoordinator.unusableBehindTunnel("tuic", false))
        assertNull(LanShareCoordinator.unusableBehindTunnel("hysteria2", true))
    }

    @Test
    fun testLanShareSettingsOpenState() {
        val s1 = LanShareSettings(enabled = true, port = 1080)
        assertTrue(s1.isOpen)

        val s2 = LanShareSettings(enabled = true, port = 1080, username = "admin", password = "secretpassword")
        assertFalse(s2.isOpen)
    }
}
