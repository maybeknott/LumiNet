package com.luminet.android.importing

import org.junit.Assert.assertEquals
import org.junit.Assert.assertNotEquals
import org.junit.Assert.assertTrue
import org.junit.Test

class ProfileKeyTest {

    @Test
    fun `same profile produces same key`() {
        val a = computeProfileKey(sampleProfile("A"))
        val b = computeProfileKey(sampleProfile("A"))
        assertEquals(a.hash, b.hash)
        assertEquals(a, b)
    }

    @Test
    fun `alias change does not change the key`() {
        val a = computeProfileKey(sampleProfile("A").copy(alias = "Iran-1"))
        val b = computeProfileKey(sampleProfile("A").copy(alias = "Iran-1-renamed"))
        assertEquals("alias is display-only and must not affect identity", a.hash, b.hash)
    }

    @Test
    fun `case differences in host do not change the key`() {
        val a = computeProfileKey(sampleProfile("A").copy(host = "Example.COM"))
        val b = computeProfileKey(sampleProfile("A").copy(host = "example.com"))
        assertEquals(a.hash, b.hash)
    }

    @Test
    fun `different port produces different key`() {
        val a = computeProfileKey(sampleProfile("A").copy(port = 443))
        val b = computeProfileKey(sampleProfile("A").copy(port = 8443))
        assertNotEquals(a.hash, b.hash)
    }

    @Test
    fun `matchProfile returns MATCH for identical keys`() {
        val a = computeProfileKey(sampleProfile("A"))
        val b = computeProfileKey(sampleProfile("A").copy(alias = "anything"))
        assertEquals(MatchDecision.MATCH, matchProfile(a, b))
    }

    @Test
    fun `matchProfile returns MISMATCH for different hosts`() {
        val a = computeProfileKey(sampleProfile("A"))
        val b = computeProfileKey(sampleProfile("A").copy(host = "other.example"))
        assertEquals(MatchDecision.MISMATCH, matchProfile(a, b))
    }

    @Test(expected = IllegalArgumentException::class)
    fun `blank host is rejected`() {
        computeProfileKey(sampleProfile("A").copy(host = " "))
    }

    @Test(expected = IllegalArgumentException::class)
    fun `out of range port is rejected`() {
        computeProfileKey(sampleProfile("A").copy(port = 100_000))
    }

    @Test
    fun `shortHash returns 12 chars`() {
        val k = computeProfileKey(sampleProfile("A"))
        assertEquals(12, k.shortHash().length)
    }

    @Test
    fun `ProfileKey hash is 64 char hex`() {
        val k = computeProfileKey(sampleProfile("A"))
        assertTrue(k.hash.matches(Regex("[0-9a-f]{64}")))
    }

    private fun sampleProfile(label: String) = V2rayProfile(
        protocol = "vless",
        host = "$label.example.com",
        port = 443,
        uuid = "11111111-2222-3333-4444-555555555555",
        password = null,
        network = "ws",
        tls = "reality",
        path = "/ws",
        sni = "$label.example.com",
        alias = label,
    )
}
