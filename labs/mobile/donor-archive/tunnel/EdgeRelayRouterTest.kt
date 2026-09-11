package com.luminet.android.tunnel

import org.junit.Assert.assertArrayEquals
import org.junit.Assert.assertEquals
import org.junit.Assert.assertTrue
import org.junit.Test
import java.net.InetAddress

class EdgeRelayRouterTest {

    @Test
    fun testDirectRouteForNormalTraffic() {
        val router = EdgeRelayRouter()
        val target = EdgeRouteTarget(
            network = "tcp",
            host = "example.com",
            port = 80,
            resolvedIp = InetAddress.getByName("93.184.216.34")
        )

        val decision = router.decideRoute(target)
        assertTrue(decision is EdgeRoutingDecision.Direct)
        val direct = decision as EdgeRoutingDecision.Direct
        assertEquals("example.com", direct.host)
        assertEquals(80, direct.port)
    }

    @Test
    fun testCloudflareIpChaining() {
        val router = EdgeRelayRouter()
        val target = EdgeRouteTarget(
            network = "tcp",
            host = "cloudflare.com",
            port = 443,
            resolvedIp = InetAddress.getByName("104.16.132.229")
        )

        val decision = router.decideRoute(target, sessionId = 1L)
        assertTrue(decision is EdgeRoutingDecision.RelayChained)
        val chained = decision as EdgeRoutingDecision.RelayChained
        assertEquals("relay2.bepass.org", chained.relayHost)
        assertEquals(6666, chained.relayPort)
        assertEquals("tcp@cloudflare.com$443\r\n", chained.delimiterHeader)
    }

    @Test
    fun testUdpChaining() {
        val router = EdgeRelayRouter()
        val target = EdgeRouteTarget(
            network = "udp",
            host = "8.8.8.8",
            port = 53,
            resolvedIp = InetAddress.getByName("8.8.8.8")
        )

        val decision = router.decideRoute(target, sessionId = 2L)
        assertTrue(decision is EdgeRoutingDecision.RelayChained)
        val chained = decision as EdgeRoutingDecision.RelayChained
        assertEquals("relay3.bepass.org", chained.relayHost)
        assertEquals("udp@8.8.8.8$53\r\n", chained.delimiterHeader)
    }

    @Test
    fun testSessionHashSelection() {
        val router = EdgeRelayRouter()

        assertEquals("relay1.bepass.org", router.selectRelayEndpoint(0L).first)
        assertEquals("relay2.bepass.org", router.selectRelayEndpoint(1L).first)
        assertEquals("relay3.bepass.org", router.selectRelayEndpoint(2L).first)
        assertEquals("relay1.bepass.org", router.selectRelayEndpoint(3L).first)
        assertEquals("relay1.bepass.org", router.selectRelayEndpoint(null).first)
    }

    @Test
    fun testFallbackRoute() {
        val router = EdgeRelayRouter()
        val target = EdgeRouteTarget(
            network = "tcp",
            host = "api.service.io",
            port = 443
        )

        val fallback = router.buildFallbackRelayRoute(target, sessionId = 4L)
        assertTrue(fallback is EdgeRoutingDecision.RelayChained)
        val chained = fallback as EdgeRoutingDecision.RelayChained
        assertEquals("relay2.bepass.org", chained.relayHost)
        assertEquals("tcp@api.service.io$443\r\n", chained.delimiterHeader)
    }

    @Test
    fun testBuildDohAQuery() {
        val query = EdgeRelayRouter.buildDohAQuery("example.com")
        assertTrue(query.size >= 12)

        assertEquals(0x12.toByte(), query[0])
        assertEquals(0x34.toByte(), query[1])
        assertEquals(0x01.toByte(), query[2])
        assertEquals(0x00.toByte(), query[3])

        val expectedQname = byteArrayOf(
            7, 'e'.code.toByte(), 'x'.code.toByte(), 'a'.code.toByte(), 'm'.code.toByte(), 'p'.code.toByte(), 'l'.code.toByte(), 'e'.code.toByte(),
            3, 'c'.code.toByte(), 'o'.code.toByte(), 'm'.code.toByte(),
            0
        )
        val qnameActual = query.copyOfRange(12, 12 + expectedQname.size)
        assertArrayEquals(expectedQname, qnameActual)

        val tail = query.copyOfRange(12 + expectedQname.size, query.size)
        assertArrayEquals(byteArrayOf(0, 1, 0, 1), tail)
    }
}
