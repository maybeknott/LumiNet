package com.luminet.android.tunnel

import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertNotNull
import org.junit.Assert.assertTrue
import org.junit.Test

class TunMapdnsTest {

    private val emitter = TunMapdns()

    @Test
    fun `emitConfig produces valid JSON`() {
        val json = emitter.emitConfig(
            entries = listOf(
                MapdnsEntry(domain = "example.com", strategy = MapdnsStrategy.proxy),
            ),
        )
        assertTrue(json.contains("\"version\": 1"))
        assertTrue(json.contains("\"rules\""))
        assertTrue(json.contains("example.com"))
        assertTrue(json.contains("proxy"))
    }

    @Test
    fun `emitConfig round-trips back to MapdnsConfig`() {
        val json = emitter.emitConfig(
            entries = listOf(
                MapdnsEntry(domain = "test.com", strategy = MapdnsStrategy.direct, server = "8.8.8.8"),
            ),
            defaultStrategy = MapdnsStrategy.block,
        )
        val config = emitter.parseConfig(json)
        assertEquals(1, config.version)
        assertEquals(MapdnsStrategy.block, config.defaultStrategy)
        assertEquals(1, config.rules.size)
        assertEquals("test.com", config.rules[0].domain)
        assertEquals(MapdnsStrategy.direct, config.rules[0].strategy)
        assertEquals("8.8.8.8", config.rules[0].server)
    }

    @Test
    fun `tunnelRule helper produces correct entry`() {
        val rule = emitter.tunnelRule("onion")
        assertEquals("onion", rule.domain)
        assertEquals(MapdnsStrategy.proxy, rule.strategy)
        assertTrue(rule.includeSubdomains)
    }

    @Test
    fun `blockRule helper produces correct entry`() {
        val rule = emitter.blockRule("ads.example.com", includeSubdomains = false)
        assertEquals("ads.example.com", rule.domain)
        assertEquals(MapdnsStrategy.block, rule.strategy)
        assertFalse(rule.includeSubdomains)
    }

    @Test
    fun `defaultIranConfig contains Iran TLDs`() {
        val json = emitter.defaultIranConfig()
        val config = emitter.parseConfig(json)
        assertTrue(config.rules.any { it.domain == "ir" })
        assertTrue(config.rules.any { it.domain == "onion" })
        assertEquals(MapdnsStrategy.proxy, config.defaultStrategy)
    }

    @Test
    fun `empty rules is valid`() {
        val json = emitter.emitConfig(entries = emptyList())
        val config = emitter.parseConfig(json)
        assertTrue(config.rules.isEmpty())
        assertEquals(MapdnsStrategy.direct, config.defaultStrategy)
    }

    @Test(expected = IllegalArgumentException::class)
    fun `blank domain is rejected`() {
        MapdnsEntry(domain = "  ", strategy = MapdnsStrategy.proxy)
    }

    @Test(expected = IllegalArgumentException::class)
    fun `domain starting with dot is rejected`() {
        MapdnsEntry(domain = ".example.com", strategy = MapdnsStrategy.proxy)
    }

    @Test(expected = IllegalArgumentException::class)
    fun `version out of range is rejected`() {
        val cfg = MapdnsConfig(version = 99, rules = emptyList())
    }

    @Test
    fun `orbotPattern returns domain as-is when not wildcard`() {
        val entry = MapdnsEntry(domain = "example.com", strategy = MapdnsStrategy.proxy)
        assertEquals("example.com", entry.orbotPattern())
    }

    @Test
    fun `orbotPattern preserves wildcard prefix`() {
        val entry = MapdnsEntry(domain = "*.example.com", strategy = MapdnsStrategy.proxy)
        assertEquals("*.example.com", entry.orbotPattern())
    }

    @Test
    fun `JSON output contains strategy enum names not ordinals`() {
        val json = emitter.emitConfig(
            entries = listOf(MapdnsEntry(domain = "test.net", strategy = MapdnsStrategy.block)),
        )
        assertTrue("JSON should contain enum name 'block', not numeric ordinal", json.contains("block"))
        assertFalse("JSON should not contain numeric ordinal", json.contains("\"strategy\": 2"))
    }

    @Test
    fun `tunnelIds field appears in JSON when non-empty`() {
        val json = emitter.emitConfig(
            entries = emptyList(),
            tunnelIds = listOf("tunnel-alpha", "tunnel-beta"),
        )
        assertTrue(json.contains("tunnel-alpha"))
        assertTrue(json.contains("tunnel-beta"))
    }

    @Test
    fun `parseConfig handles unknown fields gracefully`() {
        val sloppyJson = """
            {
              "version": 1,
              "defaultStrategy": "direct",
              "rules": [],
              "tunnelIds": [],
              "unknownField": "ignored"
            }
        """.trimIndent()
        val config = emitter.parseConfig(sloppyJson)
        assertEquals(1, config.version)
        assertEquals(MapdnsStrategy.direct, config.defaultStrategy)
    }

    @Test
    fun `includeSubdomains serialises correctly`() {
        val entry = MapdnsEntry(domain = "a.com", strategy = MapdnsStrategy.proxy, includeSubdomains = false)
        val json = emitter.emitConfig(entries = listOf(entry))
        assertTrue(json.contains("\"includeSubdomains\": false"))
    }
}
