package com.luminet.android.tunnel

import org.json.JSONObject
import org.junit.Assert.*
import org.junit.Test

class CoreConfigContextBuilderTest {

    @Test
    fun testBuildSingleNormalProfile() {
        val profile = OutboundProfileItem(
            guid = "guid-1",
            remarks = "Node A",
            server = "1.2.3.4",
            port = 443
        )
        val profiles = mapOf("guid-1" to profile)

        val context = CoreConfigContextBuilder.build("guid-1", profiles)
        assertNotNull(context)
        assertFalse(context!!.isCustom)
        assertEquals(1, context.resolvedOutbounds.size)
        assertEquals(CoreResolvedType.NORMAL, context.resolvedOutbounds[0].resolvedType)
    }

    @Test
    fun testBuildProxyChain() {
        val hop1 = OutboundProfileItem(
            guid = "guid-hop1",
            remarks = "Hop 1",
            server = "1.1.1.1",
            port = 443
        )
        val exit = OutboundProfileItem(
            guid = "guid-exit",
            remarks = "Exit Node",
            server = "2.2.2.2",
            port = 8388,
            proxyChainProfiles = "Hop 1"
        )
        val profiles = mapOf(
            "guid-hop1" to hop1,
            "guid-exit" to exit
        )

        val context = CoreConfigContextBuilder.build("guid-exit", profiles)
        assertNotNull(context)
        assertEquals(1, context!!.resolvedOutbounds.size)
        val outbound = context.resolvedOutbounds[0]
        assertEquals(CoreResolvedType.PROXYCHAIN, outbound.resolvedType)
        assertEquals(2, outbound.resolvedProfiles.size)
        assertEquals("Hop 1", outbound.resolvedProfiles[0].remarks)
        assertEquals("Exit Node", outbound.resolvedProfiles[1].remarks)
    }

    @Test
    fun testStripConfigForSpeedtest() {
        val fullConfig = JSONObject().apply {
            put("outbounds", org.json.JSONArray().apply {
                put(JSONObject().put("tag", "proxy_1").put("protocol", "vless"))
                put(JSONObject().put("tag", "direct").put("protocol", "freedom"))
            })
        }.toString()

        val speedConfigStr = CoreConfigContextBuilder.stripConfigForSpeedtest(fullConfig, "proxy_1", 10888)
        val speedConfig = JSONObject(speedConfigStr)

        val inbounds = speedConfig.getJSONArray("inbounds")
        assertEquals(1, inbounds.length())
        assertEquals(10888, inbounds.getJSONObject(0).getInt("port"))

        val outbounds = speedConfig.getJSONArray("outbounds")
        assertEquals(2, outbounds.length())
        assertEquals("proxy_1", outbounds.getJSONObject(0).getString("tag"))
    }
}
