package com.luminet.android.tunnel

import org.junit.Assert.*
import org.junit.Test

class Batch10AndroidTest {

    @Test
    fun testMeshWireguardCoordinator() {
        val coord = MeshWireguardCoordinator("node-local", "100.64.0.1")
        coord.registerDerpRelay(1, "derp-nyc.luminet.net")

        val peer = AndroidMeshPeer(
            peerId = "peer-1",
            publicKeyHex = "abcd1234ef",
            virtualIp = "100.64.0.2",
            allowedIps = listOf("10.50.0.0/16"),
            endpoints = listOf("203.0.113.5:51820"),
            derpRegionId = 1,
            lastHandshakeMs = 10_000L,
            isExitNode = true
        )
        coord.registerPeer(peer)

        assertEquals("peer-1", coord.lookupRoute("100.64.0.2"))
        assertEquals("peer-1", coord.lookupRoute("10.50.1.2"))
        assertNull(coord.lookupRoute("8.8.8.8"))

        val directEp = coord.selectBestEndpoint("peer-1", 15_000L)
        assertNotNull(directEp)
        assertEquals(AndroidMeshMode.DIRECT, directEp!!.first)

        val cfg = coord.generatePeerConfig("peer-1")
        assertTrue(cfg.contains("[Peer]"))
        assertTrue(cfg.contains("PersistentKeepalive = 25"))
    }

    @Test
    fun testMeshSocks5Bridge() {
        val bridge = MeshSocks5Bridge(1080)
        assertEquals(0x00.toByte(), bridge.parseGreeting(byteArrayOf(0x05, 0x01, 0x00)))

        bridge.addUser("alice", "secret123")
        assertEquals(0xFF.toByte(), bridge.parseGreeting(byteArrayOf(0x05, 0x01, 0x00)))
        assertEquals(0x02.toByte(), bridge.parseGreeting(byteArrayOf(0x05, 0x01, 0x02)))
        assertTrue(bridge.authenticate("alice", "secret123"))

        bridge.setExitNode(AndroidMeshExitNode("exit-1", "100.64.0.99", true))
        val route = bridge.evaluateRoute("example.com", 443)
        assertEquals(AndroidSocks5Disposition.MESH_EXIT, route.first)
        assertEquals("100.64.0.99", route.second)

        val reply = bridge.craftReply(0x00.toByte(), "127.0.0.1", 1080)
        assertEquals(0x05.toByte(), reply[0])
        assertEquals(0x00.toByte(), reply[1])
    }

    @Test
    fun testMultiprotocolTrafficInspector() {
        val inspector = MultiprotocolTrafficInspector()
        val ssh = "SSH-2.0-OpenSSH_8.9\r\n".toByteArray(Charsets.UTF_8)
        val resSsh = inspector.inspectStream(ssh)
        assertEquals(AndroidInspectedProto.SSH, resSsh.first)
        assertEquals(AndroidVerdict.PERMITTED, resSsh.second)

        val rdp = byteArrayOf(0x03, 0x00, 0x00, 0x13)
        val resRdp = inspector.inspectStream(rdp)
        assertEquals(AndroidInspectedProto.RDP, resRdp.first)
        assertEquals(AndroidVerdict.PERMITTED, resRdp.second)

        val http = "GET /index.html HTTP/1.1\r\nHost: site.com\r\n\r\n".toByteArray(Charsets.UTF_8)
        val resHttp = inspector.inspectStream(http)
        assertEquals(AndroidInspectedProto.HTTP, resHttp.first)
        assertEquals(AndroidVerdict.PERMITTED, resHttp.second)
    }

    @Test
    fun testStealthBridgeCollector() {
        val col = StealthBridgeCollector()
        val line = "obfs4 192.0.2.1:443 7325514E91D3B62042C026C1F740E7DF98E2A180 cert=test1234 iat-mode=0"
        val bridge = col.parseBridgeLine(line)
        assertEquals(AndroidPluggableTransport.OBFS4, bridge.transport)
        assertEquals("test1234", bridge.params["cert"])

        col.recordHealth(bridge.fingerprint, 120, true)
        val best = col.getBestBridges(AndroidPluggableTransport.OBFS4, 5)
        assertEquals(1, best.size)
        assertTrue(best[0].verified)
    }

    @Test
    fun testSplitTunnelRuleSync() {
        val sync = SplitTunnelRuleSync(AndroidSplitAction.BYPASS_VPN)
        sync.addRule("r1", "10.0.0.0/8", AndroidSplitAction.ROUTE_THROUGH_VPN, 10)
        sync.addRule("r2", "10.1.2.0/24", AndroidSplitAction.BYPASS_VPN, 20)

        assertEquals(AndroidSplitAction.BYPASS_VPN, sync.matchIp("10.1.2.55"))
        assertEquals(AndroidSplitAction.ROUTE_THROUGH_VPN, sync.matchIp("10.5.0.1"))
        assertEquals(AndroidSplitAction.BYPASS_VPN, sync.matchIp("1.1.1.1"))
    }

    @Test
    fun testDynamicProxyValidator() {
        val validator = DynamicProxyValidator()
        assertTrue(validator.verifySocks5Response(byteArrayOf(0x05, 0x00)))
        assertFalse(validator.verifySocks5Response(byteArrayOf(0x05, 0xFF.toByte())))

        val headers = mapOf("via" to "1.1 squid")
        assertEquals(AndroidProxyAnon.ANONYMOUS, validator.determineAnonymity(headers, "1.2.3.4"))

        validator.recordProbe("1.2.3.4", 8080, AndroidProxyProto.HTTP, true, 100L, AndroidProxyAnon.ELITE, 1000L)
        val healthy = validator.getHealthyProxies(200L)
        assertEquals(1, healthy.size)
    }

    @Test
    fun testNatTraversalTunnel() {
        val tunnel = NatTraversalTunnel("peer-a", AndroidNatType.RESTRICTED_CONE)
        val pkt = tunnel.craftPunchPacket(123)
        val parsed = tunnel.parsePunchPacket(pkt)
        assertNotNull(parsed)
        assertEquals(123, parsed!!.first)
        assertEquals("peer-a", parsed.second)

        assertTrue(tunnel.canDirectPunch(AndroidNatType.FULL_CONE, AndroidNatType.SYMMETRIC))
        assertFalse(tunnel.canDirectPunch(AndroidNatType.SYMMETRIC, AndroidNatType.SYMMETRIC))

        val cand = AndroidPeerCandidate("peer-b", "1.1.1.1:5000", "2.2.2.2:5000", AndroidNatType.FULL_CONE)
        assertEquals(AndroidPunchState.PROBING, tunnel.initiatePeerPunch(cand))
    }

    @Test
    fun testCommunityFeedParser() {
        val parser = CommunityFeedParser()
        val vless = "vless://user-uuid@example.com:443?type=ws&sni=cdn.example.com#US-East"
        val node = parser.parseUri(vless)
        assertNotNull(node)
        assertEquals("vless", node!!.protocol)
        assertEquals("example.com", node.server)
        assertEquals(443, node.port)
        assertEquals("cdn.example.com", node.sni)
    }

    @Test
    fun testCoreEngineSupervisor() {
        val supervisor = CoreEngineSupervisor(AndroidSupervisorConfig(maxRestarts = 2))
        assertTrue(supervisor.start(1234))
        assertEquals(AndroidCoreEngineState.RUNNING, supervisor.state)

        supervisor.handleProcessExit(1)
        assertEquals(AndroidCoreEngineState.DEGRADED, supervisor.state)
        supervisor.handleProcessExit(1)
        assertEquals(AndroidCoreEngineState.DEGRADED, supervisor.state)
        supervisor.handleProcessExit(1)
        assertEquals(AndroidCoreEngineState.CRASHED, supervisor.state)
    }

    @Test
    fun testAsyncRuleEvaluator() {
        val eval = AsyncRuleEvaluator("DIRECT")
        eval.addRule(AndroidRoutingRule(
            kind = AndroidRuleKind.DOMAIN_SUFFIX,
            value = "google.com",
            targetOutbound = "PROXY",
            priority = 100
        ))
        val target = AndroidTrafficTarget(domain = "maps.google.com")
        assertEquals("PROXY", eval.evaluate(target))

        val unknown = AndroidTrafficTarget(domain = "other.org")
        assertEquals("DIRECT", eval.evaluate(unknown))
    }

    @Test
    fun testRelayRotationCircuitBreaker() {
        val cb = RelayRotationCircuitBreaker(AndroidCircuitBreakerConfig(failureThreshold = 2, cooldownMs = 5000L))
        cb.registerRelay("r1", "1.1.1.1:443")
        cb.registerRelay("r2", "2.2.2.2:443")

        assertEquals("r1", cb.selectActiveRelay(1000L))
        cb.recordFailure("r1", 1000L)
        cb.recordFailure("r1", 1000L)
        assertEquals("r2", cb.selectActiveRelay(1000L))

        // Fail r2 as well
        cb.recordFailure("r2", 1000L)
        cb.recordFailure("r2", 1000L)

        // After cooldown, r1 becomes half-open
        assertEquals("r1", cb.selectActiveRelay(7000L))
    }

    @Test
    fun testOnDeviceDpiEvader() {
        val evader = OnDeviceDpiEvader(2)
        val tls = byteArrayOf(0x16, 0x03, 0x01, 0x00, 0x10)
        val frags = evader.applySniSplit(tls, 2)
        assertEquals(2, frags.size)
        assertEquals(2, frags[0].size)

        val http = "GET / HTTP/1.1\r\nHost: badsite.com\r\n\r\n".toByteArray(Charsets.UTF_8)
        val desynced = String(evader.applyHttpDesync(http), Charsets.UTF_8)
        assertTrue(desynced.contains("hOst: badsite.com"))
    }

    @Test
    fun testUniversalMeshEvasionPipeline() {
        val pipeline = UniversalMeshEvasionPipeline("peer-x")
        val direct = pipeline.processOutboundFrame("TEST_FRAME".toByteArray(Charsets.UTF_8))
        assertEquals(1, direct.size)

        // 3 failures escalate to HOLE_PUNCHED_MESH
        pipeline.reportFailure(); pipeline.reportFailure()
        val t1 = pipeline.reportFailure()
        assertEquals(AndroidPipelineTier.HOLE_PUNCHED_MESH, t1)

        // 3 failures escalate to DPI_EVADED_MESH
        pipeline.reportFailure(); pipeline.reportFailure()
        val t2 = pipeline.reportFailure()
        assertEquals(AndroidPipelineTier.DPI_EVADED_MESH, t2)
        val frags = pipeline.processOutboundFrame("0123456789".toByteArray(Charsets.UTF_8))
        assertEquals(2, frags.size)

        // 3 failures escalate to STEALTH_BRIDGE_FALLBACK
        pipeline.reportFailure(); pipeline.reportFailure()
        val t3 = pipeline.reportFailure()
        assertEquals(AndroidPipelineTier.STEALTH_BRIDGE_FALLBACK, t3)
        val stealth = pipeline.processOutboundFrame("ABC".toByteArray(Charsets.UTF_8))
        assertTrue(String(stealth[0], Charsets.UTF_8).startsWith("STH:"))
    }

    @Test
    fun testAutonomousGlobalProxySupervisor() {
        val sup = AutonomousGlobalProxySupervisor(true)
        sup.registerSubsystem("mesh", "routing")
        sup.registerSubsystem("dpi", "evasion")

        sup.updateHealth("mesh", true, 15, 1000L)
        sup.updateHealth("dpi", false, 0, 1000L, "DPI error")

        val report = sup.generateReport()
        assertEquals(2, report.totalSubsystems)
        assertEquals(1, report.healthySubsystems)
        assertEquals(15, report.totalActiveConnections)

        sup.setKillswitch(true)
        val postKill = sup.generateReport()
        assertEquals(0, postKill.totalActiveConnections)
        assertTrue(postKill.killswitchEngaged)

        val targets = sup.identifyRemediationTargets(2000L, 5000L)
        assertEquals(listOf("dpi"), targets)
    }
}
