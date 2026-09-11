package com.luminet.android.scanner

import kotlinx.coroutines.runBlocking
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertTrue
import org.junit.Test

class DnsScannerEngineTest {

    @Test
    fun `test ipv4 math parsing and masking`() {
        val prefix = Ipv4Math.parsePrefix("192.168.1.130/24")
        assertEquals(24, prefix.prefixLength)
        assertEquals("192.168.1.0/24", prefix.normalizedString())
        assertEquals(256L, prefix.addressCount())
        assertEquals(254L, prefix.usableHostCount())

        val bounds = prefix.hostBounds()
        requireNotNull(bounds)
        assertEquals("192.168.1.1", Ipv4Math.formatAddress(bounds.first))
        assertEquals("192.168.1.254", Ipv4Math.formatAddress(bounds.last))
    }

    @Test
    fun `test host walker emission limits`() = runBlocking {
        val walker = HostWalker()
        val hosts = mutableListOf<String>()

        val count = walker.walk(
            prefixes = listOf("10.0.0.0/29"), // 6 usable hosts: .1 through .6
            limit = 4,
        ) { addr, _ ->
            hosts.add(addr)
            true
        }

        assertEquals(4L, count)
        assertEquals(4, hosts.size)
        assertEquals("10.0.0.1", hosts[0])
        assertEquals("10.0.0.4", hosts[3])
    }

    @Test
    fun `test target input normalizer`() {
        val rawInput = """
            1.1.1.1, 8.8.8.8
            192.168.1.0/24
            
            9.9.9.9
        """.trimIndent()

        val normalized = TargetInputNormalizer.normalizeImportedTargets(rawInput)
        val lines = normalized.lines()
        assertEquals(4, lines.size)
        assertEquals("1.1.1.1", lines[0])
        assertEquals("8.8.8.8", lines[1])
        assertEquals("192.168.1.0/24", lines[2])
        assertEquals("9.9.9.9", lines[3])
    }

    @Test
    fun `test nearby IP generation`() {
        val center = "10.0.0.10"
        val nearby = DnsScannerEngine.generateNearbyIps(center, listOf(-2, -1, 1, 2, -500, 500))
        assertEquals(4, nearby.size)
        assertTrue(nearby.contains("10.0.0.8"))
        assertTrue(nearby.contains("10.0.0.9"))
        assertTrue(nearby.contains("10.0.0.11"))
        assertTrue(nearby.contains("10.0.0.12"))
        assertFalse(nearby.contains(center))
    }

    @Test
    fun `test tunnel realism qname format and scoring`() {
        val qname = DnsScannerEngine.generateTunnelRealismQName("example.com")
        assertTrue(qname.endsWith(".example.com."))
        val label = qname.substringBefore('.')
        assertEquals(57, label.length)

        val perfectScore = DnsScannerEngine.computeTunnelScore(
            nsOk = true,
            txtOk = true,
            randomSubOk = true,
            realismOk = true,
            edns0Supported = true,
            nxdomainRatio = 0.8,
        )
        assertEquals(6, perfectScore)

        val partialScore = DnsScannerEngine.computeTunnelScore(
            nsOk = true,
            txtOk = false,
            randomSubOk = true,
            realismOk = false,
            edns0Supported = false,
            nxdomainRatio = 0.5,
        )
        assertEquals(2, partialScore)
    }
}
