package com.luminet.android.tunnel

import org.junit.Assert.*
import org.junit.Test

class Batch4AndroidTest {

    @Test
    fun test46_dnsWizardConfigGenerator() {
        val gen = DnsWizardConfigGenerator()
        val res = gen.generate(DnsWizardConfig("FastDNS", "8.8.8.8", "dns.test", "obfskey"))
        assertTrue(res.isReady)
        assertTrue(res.uri.contains("dnsvpn://obfskey@8.8.8.8:53"))
    }

    @Test
    fun test47_subnetRangeScout() {
        val scout = SubnetRangeScout(maxRttMsThreshold = 250L)
        val report = scout.scout("192.168.1", 5)
        assertEquals(5, report.totalTested)
        assertTrue(report.cleanCount > 0)
    }

    @Test
    fun test48_tcpRendezvousBridge() {
        val bridge = TcpRendezvousBridge()
        val token = bridge.register("1.1.1.1:5000")
        val sess = bridge.connect(token, "2.2.2.2:6000")
        assertTrue(sess.isConnected)
        assertEquals("2.2.2.2:6000", sess.responder)
    }

    @Test
    fun test49_domainFrontingTransport() {
        val transport = DomainFrontingTransport()
        val req = transport.prepare(DomainFrontingConfig("front.cdn.net", "target.origin.com", "/api/v1"))
        assertEquals("front.cdn.net", req.sniDomain)
        assertTrue(req.rawHeaderString.contains("Host: target.origin.com"))
    }

    @Test
    fun test50_serverlessTunnelCarrier() {
        val carrier = ServerlessTunnelCarrier()
        val frame = ServerlessFrame(7, true, "EDGE_FRAME".toByteArray())
        val encoded = carrier.encode(frame)
        val decoded = carrier.decode(encoded)
        assertEquals(7, decoded.streamId)
        assertTrue(decoded.isEof)
        assertEquals("EDGE_FRAME", String(decoded.payload))
    }

    @Test
    fun test51_processSupervisor() {
        val sup = ProcessSupervisor(maxRestarts = 2, baseBackoffMs = 100L)
        val b1 = sup.recordCrash()
        assertEquals(100L, b1)
        val b2 = sup.recordCrash()
        assertEquals(200L, b2)
        val b3 = sup.recordCrash()
        assertNull(b3) // exceeded limit
    }

    @Test
    fun test52_httpRelayTunnelClient() {
        val client = HttpRelayTunnelClient(RelayClientConfig("relay.luminet", 8080, "sec-token", "1.1.1.1", 443))
        val payload = client.buildConnectPayload()
        assertTrue(payload.startsWith("CONNECT 1.1.1.1:443 HTTP/1.1"))
        assertTrue(payload.contains("Proxy-Authorization: Bearer sec-token"))
    }

    @Test
    fun test53_subscriptionPipeline() {
        val pipeline = SubscriptionPipeline()
        val raw = "vless://u1@1.1.1.1:443#Node1\ntrojan://p1@2.2.2.2:443#Node2\nvless://u1@1.1.1.1:443#Node1"
        val nodes = pipeline.parse(raw)
        assertEquals(2, nodes.size)
        assertEquals("vless", nodes[0].protocol)
        assertEquals("Node1", nodes[0].tag)
    }

    @Test
    fun test54_rawPacketCarrier() {
        val carrier = RawPacketCarrier()
        val payload = "ETHERNET_L3_DATA".toByteArray()
        val encoded = carrier.encode(1, 10, payload)
        assertTrue(encoded.size > 16)
    }

    @Test
    fun test55_dnsArqWindowCodec() {
        val codec = DnsArqWindowCodec("tunnel.net")
        val q = codec.formatQuery(0, false, "aa11")
        val chunk = codec.parseQuery(q)
        assertNotNull(chunk)
        assertEquals(0, chunk!!.seq)
        assertFalse(chunk.isLast)
    }

    @Test
    fun test56_tcpDesyncPoisoner() {
        val poisoner = TcpDesyncPoisoner()
        val data = "HELLO_WORLD".toByteArray()
        val plan = poisoner.plan(data, DesyncType.SPLIT, 5)
        assertEquals(2, plan.parts.size)
        assertEquals("HELLO", String(plan.parts[0]))
    }

    @Test
    fun test57_subnetNeighborScanner() {
        val scanner = SubnetNeighborScanner()
        val peers = scanner.scan("10.0.0", 80, 4)
        assertEquals(4, peers.size)
        assertTrue(peers[0].isGateway)
    }

    @Test
    fun test58_uptimeTracker() {
        val tracker = UptimeTracker(10)
        tracker.record(true, 50)
        tracker.record(true, 40)
        tracker.record(false, 0)
        tracker.record(true, 45)
        assertEquals(75.0, tracker.availability(), 0.01)
    }

    @Test
    fun test59_sslVpnVirtualAdapter() {
        val adapter = SslVpnVirtualAdapter(SslVpnConfig("10.0.0.1", "10.0.0.50"))
        assertTrue(adapter.activate())
        assertTrue(adapter.heartbeat())
        adapter.recordTraffic(100, 200)
        assertEquals(100L, adapter.rxBytes)
    }

    @Test
    fun test60_upstreamMatrix() {
        val matrix = UpstreamMatrix()
        matrix.register(AndroidUpstreamNode("n1", "vless", "1.1.1.1:443", 200, true))
        matrix.register(AndroidUpstreamNode("n2", "trojan", "2.2.2.2:443", 50, true))
        matrix.register(AndroidUpstreamNode("n3", "vmess", "3.3.3.3:443", 10, false))
        val best = matrix.selectBest()
        assertNotNull(best)
        assertEquals("n2", best!!.id)
    }

    @Test
    fun testConvergence_evasionOrchestrator() {
        val orch = AutonomousEvasionOrchestrator(rstThreshold = 2)
        assertEquals(AndroidEvasionMode.STANDARD, orch.mode)
        orch.recordTcpReset()
        val m2 = orch.recordTcpReset()
        assertEquals(AndroidEvasionMode.SPLIT, m2)
    }

    @Test
    fun testConvergence_multipathGateway() {
        val coord = MultipathGatewayCoordinator()
        coord.registerLink(AndroidEgressLink("link1", 20, true))
        coord.registerLink(AndroidEgressLink("link2", 40, true))
        val l1 = coord.routePacket(1000)
        val l2 = coord.routePacket(1000)
        assertNotEquals(l1, l2)
    }
}
