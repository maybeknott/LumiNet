package com.luminet.android.tunnel

import org.junit.Assert.*
import org.junit.Test

class Batch2AndroidTest {

    @Test
    fun testZeroTrustRouteTable() {
        val table = ZeroTrustRouteTable()
        val res = ZeroTrustResource("res1", "Database", "10.0.0.0/24", "100.64.0.10", 0x03)
        table.registerResource(res)

        val found = table.lookupByIp("100.64.0.10")
        assertNotNull(found)
        assertEquals("Database", found?.name)

        assertTrue(table.evaluateAccess("100.64.0.10", 0x03))
        assertTrue(table.evaluateAccess("100.64.0.10", 0x07))
        assertFalse(table.evaluateAccess("100.64.0.10", 0x01))
    }

    @Test
    fun testNoisePacketInjector() {
        val inj = NoisePacketInjector()
        val frame = inj.synthesizeNoiseFrame(12345L)
        assertTrue(frame.size >= 13)
        assertEquals(0x17.toByte(), frame[0])
        assertEquals(0x03.toByte(), frame[1])
        assertEquals(0x03.toByte(), frame[2])
    }

    @Test
    fun testDynamicCaManager() {
        val ca = DynamicCaManager()
        val c1 = ca.issueOrGetCert("api.internal", 3600_000L)
        val c2 = ca.issueOrGetCert("api.internal", 3600_000L)
        assertEquals(c1.serialNumber, c2.serialNumber)

        val c3 = ca.issueOrGetCert("db.internal", 3600_000L)
        assertNotEquals(c1.serialNumber, c3.serialNumber)
    }

    @Test
    fun testStaticCidrPool() {
        val pool = StaticCidrPool()
        val client = pool.allocateClient("u1", "pubKeyA==")
        assertNotNull(client)
        assertEquals("10.66.0.2", client?.allocatedIp)

        assertFalse(pool.isKeyRevoked("pubKeyA=="))
        assertTrue(pool.revokeClient("10.66.0.2"))
        assertTrue(pool.isKeyRevoked("pubKeyA=="))
    }

    @Test
    fun testBandwidthQuotaEnforcer() {
        val enforcer = BandwidthQuotaEnforcer()
        enforcer.registerUser("alice", 1000L)

        assertEquals(QuotaAlertLevel.NORMAL, enforcer.recordTraffic("alice", 500L))
        assertTrue(enforcer.isUserAllowed("alice"))

        assertEquals(QuotaAlertLevel.WARNING_80, enforcer.recordTraffic("alice", 350L))
        assertTrue(enforcer.isUserAllowed("alice"))

        assertEquals(QuotaAlertLevel.EXHAUSTED, enforcer.recordTraffic("alice", 200L))
        assertFalse(enforcer.isUserAllowed("alice"))
    }

    @Test
    fun testMultihopRelayChain() {
        val entry = RelayHop(0, "1.1.1.1:51820", "pub1")
        val exit = RelayHop(1, "2.2.2.2:51820", "pub2")
        val chain = MultihopRelayChain(entry, exit, ByteArray(32))

        val (entryIps, exitIps) = chain.getNestedAllowedIps()
        assertEquals("10.64.0.1/32", entryIps)
        assertEquals("0.0.0.0/0, ::/0", exitIps)
    }

    @Test
    fun testHeaderInterceptRouter() {
        val router = HeaderInterceptRouter()
        router.addRule("x-telepresence-intercept-id", "dev-alice", "127.0.0.1:9090")

        assertNull(router.evaluateHeaders(mapOf("User-Agent" to "curl/7.0")))
        val target = router.evaluateHeaders(mapOf("X-Telepresence-Intercept-Id" to "dev-alice"))
        assertEquals("127.0.0.1:9090", target)
    }

    @Test
    fun testLatencyRaceSelector() {
        val racer = LatencyRaceSelector()
        racer.registerNode("n1", "vless", "1.1.1.1:443")
        racer.registerNode("n2", "ss", "2.2.2.2:443")

        racer.recordProbe("n1", 100.0)
        racer.recordProbe("n2", 40.0)

        val fastest = racer.selectFastest()
        assertNotNull(fastest)
        assertEquals("n2", fastest?.nodeId)
    }

    @Test
    fun testHotspotNatRepeater() {
        val repeater = HotspotNatRepeater()
        val rules = repeater.generateIptables()
        assertTrue(rules.any { it.contains("-o tun0 -j MASQUERADE") })
        assertTrue(rules.any { it.contains("TCPMSS --set-mss 1360") })
    }

    @Test
    fun testMultiprotocolConfigSynthesizer() {
        val json = MultiprotocolConfigSynthesizer.generateSingboxInbound(
            ProtocolConfigPreset(8443, "uuid1", "cdn.cloudflare.com", "tcp-reality")
        )
        assertTrue(json.contains("8443"))
        assertTrue(json.contains("cdn.cloudflare.com"))
        assertTrue(json.contains("tcp-reality"))
    }

    @Test
    fun testIdentityPolicyEvaluator() {
        val evaluator = IdentityPolicyEvaluator()
        evaluator.addPolicy(RoutePolicyRule("/admin", setOf("luminet.internal"), setOf("admins")))

        val admin = IdentitySessionData("a@luminet.internal", "luminet.internal", setOf("admins"))
        assertTrue(evaluator.isAuthorized("/admin/dashboard", admin))

        val guest = IdentitySessionData("g@other.com", "other.com", setOf("guest"))
        assertFalse(evaluator.isAuthorized("/admin/dashboard", guest))
    }

    @Test
    fun testGatewayHealthMonitor() {
        val monitor = GatewayHealthMonitor()
        monitor.registerGateway("192.0.2.1")
        monitor.registerGateway("192.0.2.2")

        monitor.recordProbe("192.0.2.1", 10.0, 0.0)
        monitor.recordProbe("192.0.2.2", 15.0, 0.0)
        assertEquals("192.0.2.1", monitor.selectActiveGateway("192.0.2.1", "192.0.2.2"))

        monitor.recordProbe("192.0.2.1", 100.0, 0.60)
        assertEquals("192.0.2.2", monitor.selectActiveGateway("192.0.2.1", "192.0.2.2"))
    }

    @Test
    fun testTcpChunkSplitter() {
        val chunks = TcpChunkSplitter.splitBytes("GET /index.html HTTP/1.1".toByteArray(), 5)
        assertEquals(5, chunks.size)
        assertEquals("GET /", String(chunks[0]))

        val mutated = TcpChunkSplitter.mutateHeaderCase("Host: example.com")
        assertEquals("hOsT: example.com", mutated)
    }

    @Test
    fun testDnsTunnelCodec() {
        val frame = DnsTunnelFrame(0x1234, 42, true, "payload".toByteArray())
        val query = DnsTunnelCodec.encodeToQuery(frame, "tunnel.example.com")
        val decoded = DnsTunnelCodec.decodeFromQuery(query, "tunnel.example.com")
        assertNotNull(decoded)
        assertEquals(0x1234, decoded?.sessionId)
        assertEquals(42, decoded?.sequence)
        assertEquals("payload", String(decoded?.payload ?: ByteArray(0)))
    }

    @Test
    fun testSubnetDnsScanner() {
        val scanner = SubnetDnsScanner("93.184.216.34")
        scanner.recordProbe("1.1.1.1", 12.0, "93.184.216.34", false)
        scanner.recordProbe("10.0.0.1", 4.0, "10.0.0.99", false) // poisoned

        val clean = scanner.selectCleanFastest()
        assertNotNull(clean)
        assertEquals("1.1.1.1", clean?.ip)
    }
}
