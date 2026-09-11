package com.luminet.android.tunnel

import org.json.JSONObject
import org.junit.Assert.assertEquals
import org.junit.Assert.assertTrue
import org.junit.Test

class SingboxConfigGeneratorTest {

    private val generator = SingboxConfigGenerator()

    @Test
    fun testParseSubscriptionAndGenerateJson() {
        val raw = """
            # Subscription Header
            vless://a1b2c3d4-e5f6-7890-abcd-ef1234567890@198.51.100.25:443?security=reality&pbk=pubkey123&sid=1234&sni=example.com#VlessReality
            trojan://secret123@trojan.example.com:443?sni=trojan.example.com#VlessReality
            // Ignored comment
        """.trimIndent()

        val nodes = generator.parseSubscription(raw)
        assertEquals(2, nodes.size)
        assertEquals("VlessReality", nodes[0].tag)
        assertEquals("VlessReality-1", nodes[1].tag) // Collision prevention tag

        val jsonStr = generator.generateConfigJson(nodes, SingboxGeneratorOptions(mixedPort = 2080, tunEnabled = true))
        val root = JSONObject(jsonStr)

        val inbounds = root.getJSONArray("inbounds")
        assertEquals(2, inbounds.length())
        assertEquals("tun", inbounds.getJSONObject(0).getString("type"))
        assertEquals("mixed", inbounds.getJSONObject(1).getString("type"))

        val outbounds = root.getJSONArray("outbounds")
        assertTrue(outbounds.length() >= 4)
        assertEquals("select", outbounds.getJSONObject(0).getString("tag"))
        assertEquals("auto", outbounds.getJSONObject(1).getString("tag"))
    }
}
