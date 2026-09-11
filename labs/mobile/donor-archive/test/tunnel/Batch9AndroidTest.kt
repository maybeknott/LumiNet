package com.luminet.android.tunnel

import org.junit.Assert.*
import org.junit.Test

class Batch9AndroidTest {

    @Test
    fun testHybridShadowV2Transport() {
        val psk = ByteArray(32) { (it + 1).toByte() }
        val transport = HybridShadowV2Transport(HybridShadowConfig(psk = psk))

        val salt = transport.generateSalt()
        assertEquals(32, salt.size)

        val subkey = transport.deriveSubkey(salt)
        assertEquals(32, subkey.size)

        assertTrue(transport.registerSalt(salt, 1000L))
        assertFalse(transport.registerSalt(salt, 1001L))

        val payload = "HELLO_SHADOW_V2".toByteArray()
        val framed = transport.framePayload(salt, payload)
        val (recSalt, recPayload) = transport.unframePayload(framed)!!
        assertArrayEquals(salt, recSalt)
        assertArrayEquals(payload, recPayload)
    }

    @Test
    fun testEnterpriseVpnController() {
        val ctrl = EnterpriseVpnController()
        ctrl.registerTenant(EnterpriseTenant("org-1", "Org One", "10.200.0.0/16", 5))

        val user = EnterpriseUserProfile(
            username = "alice",
            orgId = "org-1",
            role = EnterpriseRole.STANDARD_USER,
            token = "tok-alice",
            virtualIp = "10.200.1.2",
            allowedRoutes = listOf("10.200.10.0/24")
        )
        assertTrue(ctrl.registerUser(user))
        assertNotNull(ctrl.authenticate("tok-alice"))

        assertTrue(ctrl.canAccessRoute("tok-alice", "10.200.10.55"))
        assertFalse(ctrl.canAccessRoute("tok-alice", "10.200.99.1"))

        assertTrue(ctrl.revokeUser("tok-alice"))
        assertNull(ctrl.authenticate("tok-alice"))
    }

    @Test
    fun testTlsSessionTunnelAdapter() {
        val adapter = TlsSessionTunnelAdapter()
        val ticket = AndroidSessionTicket("t-123", "vpn.org", ByteArray(32), 16384, 2000L)
        adapter.storeTicket(ticket)

        assertNotNull(adapter.retrieveTicket("vpn.org", 1000L))
        assertNull(adapter.retrieveTicket("vpn.org", 3000L))

        val framed = adapter.frameEarlyData("t-123", "EARLY_DATA".toByteArray())
        val (tid, payload) = adapter.unframeEarlyData(framed)!!
        assertEquals("t-123", tid)
        assertEquals("EARLY_DATA", String(payload))
    }

    @Test
    fun testProtocolProfileOrchestrator() {
        val orch = ProtocolProfileOrchestrator()
        orch.addProfile(ClientProfile("p-1", "AWG", ClientTunnelProtocol.AMNEZIA_WG, "1.2.3.4:51820", 1, "awg://..."))
        orch.addProfile(ClientProfile("p-2", "MASQUE", ClientTunnelProtocol.MASQUE, "1.2.3.5:443", 2, "masque://..."))

        assertEquals("p-1", orch.getActiveProfile()?.profileId)
        val chain = orch.getFallbackChain()
        assertEquals(2, chain.size)
        assertEquals("p-1", chain[0].profileId)
        assertEquals("p-2", chain[1].profileId)
    }

    @Test
    fun testIpsecIkev2StateMachine() {
        val secret = ByteArray(16) { 0x42 }
        val sm = IpsecIkev2StateMachine(secret)
        assertEquals(AndroidIkeState.INIT, sm.state)

        val req = sm.buildSaInitRequest(ByteArray(32) { 0x01 })
        assertEquals(AndroidIkeState.SA_INIT_SENT, sm.state)
        assertTrue(req.size >= 28)

        // Mock response
        val resp = java.nio.ByteBuffer.allocate(28).apply {
            putLong(sm.initiatorSpi)
            putLong(99999L) // responder SPI
            put(33.toByte())
            put(0x20.toByte())
            put(34.toByte())
            put(0x00.toByte())
            putInt(0)
            putInt(28)
        }.array()

        assertTrue(sm.processSaInitResponse(resp))
        assertEquals(AndroidIkeState.SA_INIT_RECV, sm.state)
        assertTrue(sm.transitionToAuth())
        assertTrue(sm.finalizeEstablished())
        assertEquals(AndroidIkeState.ESTABLISHED, sm.state)
    }

    @Test
    fun testPublicRelayAggregator() {
        val agg = PublicRelayAggregator()
        agg.ingestNode(AndroidRelayNode("n1", "shadowsocks", "1.1.1.1", 8388, "US", 50))
        agg.ingestNode(AndroidRelayNode("n2", "vless", "1.1.1.2", 443, "US", 20))
        agg.ingestNode(AndroidRelayNode("n3", "vless", "1.1.1.3", 443, "DE", 10))

        assertEquals(3, agg.totalCount())
        val us = agg.queryRelays("US", null, 10)
        assertEquals(2, us.size)
        assertEquals("n2", us[0].nodeId) // lower ping first
    }

    @Test
    fun testEntropyScrambledTunnel() {
        val key = ByteArray(32) { 0x33 }
        val tunnel = EntropyScrambledTunnel(key, 8, 32)

        val plaintext = ByteArray(128) { 0 }
        val scrambled = tunnel.scramblePacket(plaintext, 42L)
        assertTrue(EntropyScrambledTunnel.calculateShannonEntropy(scrambled) > 4.0)

        val descrambled = tunnel.descramblePacket(scrambled, 42L)
        assertNotNull(descrambled)
        assertArrayEquals(plaintext, descrambled)
    }

    @Test
    fun testMultiprotoEgressSelector() {
        val sel = MultiprotoEgressSelector()
        sel.addTarget(AndroidEgressTarget("t1", "wireguard", 10, 100, 1.0))
        sel.addTarget(AndroidEgressTarget("t2", "vless", 10, 20, 0.0))

        val best = sel.selectBest()
        assertNotNull(best)
        assertEquals("t2", best!!.targetId)
    }

    @Test
    fun testReverseTunnelRelay() {
        val relay = ReverseTunnelRelay(10)
        val id = relay.openSession("1.1.1.1:1000", "10.0.0.1:80")
        assertNotNull(id)
        assertEquals(1, relay.activeSessions())

        assertTrue(relay.recordTraffic(id!!, 512, 1024))
        assertTrue(relay.closeSession(id))
        assertEquals(0, relay.activeSessions())
    }

    @Test
    fun testPppTlsTunnelCodec() {
        val codec = PppTlsTunnelCodec(true)
        val payload = "PPP_PAYLOAD".toByteArray()
        val frame = codec.encodeFrame(0x0021.toShort(), payload)

        val (proto, recovered) = codec.decodeFrame(frame)!!
        assertEquals(0x0021.toShort(), proto)
        assertArrayEquals(payload, recovered)
    }

    @Test
    fun testMasqueDatagramTunnel() {
        val tunnel = MasqueDatagramTunnel(123)
        val payload = "MASQUE_UDP_DATA".toByteArray()
        val enc = tunnel.encodeDatagram(payload)

        val (ctx, dec) = tunnel.decodeDatagram(enc)!!
        assertEquals(123L, ctx)
        assertArrayEquals(payload, dec)
    }

    @Test
    fun testAmneziaObfsParameters() {
        val cfg = AmneziaObfsConfig()
        assertTrue(cfg.isValid())
        assertTrue(cfg.parseLine("Jc = 8"))
        assertEquals(8, cfg.jc)
        assertTrue(cfg.parseLine("H1 = 0x11223344"))
        assertEquals(0x11223344L, cfg.h1)
    }

    @Test
    fun testNodeDiversitySampler() {
        val sampler = NodeDiversitySampler()
        sampler.addNode(AndroidDiversityNode("n1", 13335, "US", 20))
        sampler.addNode(AndroidDiversityNode("n2", 13335, "DE", 35))
        sampler.addNode(AndroidDiversityNode("n3", 16509, "JP", 80))

        val metrics = sampler.computeMetrics()
        assertEquals(3, metrics.totalNodes)
        assertEquals(2, metrics.uniqueAsns)
        assertEquals(3, metrics.uniqueCountries)
        assertTrue(metrics.diversityScore > 50.0)

        val subset = sampler.sampleDiverseSubset(2)
        assertEquals(2, subset.size)
        assertEquals("n1", subset[0])
        assertEquals("n3", subset[1])
    }

    @Test
    fun testLeakGuardSupervisor() {
        val guard = LeakGuardSupervisor("tun0", listOf("10.0.0.1"), true)
        assertTrue(guard.validateOutbound("10.0.0.1", 53, "eth0"))
        assertFalse(guard.validateOutbound("192.168.1.1", 53, "eth0"))
        assertFalse(guard.validateOutbound("2001:db8::1", 443, "eth0"))
        assertEquals(2, guard.totalLeaks())
    }

    @Test
    fun testOvpnConfigTranspiler() {
        val raw = """
            client
            dev tun
            proto udp
            remote vpn.server.io 1194
            cipher AES-256-GCM
            auth SHA256
        """.trimIndent()

        val transpiler = OvpnConfigTranspiler()
        val parsed = transpiler.transpile(raw)
        assertNotNull(parsed)
        assertEquals("vpn.server.io", parsed!!.remoteHost)
        assertEquals(1194, parsed.remotePort)
        assertEquals("udp", parsed.proto)
    }

    @Test
    fun testMasqueAmneziaHybridTunnel() {
        val hybrid = MasqueAmneziaHybridTunnel(55, AmneziaObfsConfig(jc = 3, s1 = 16))
        val preamble = hybrid.generateHandshakePreamble("WG_PUBKEY".toByteArray())
        assertEquals(4, preamble.size) // 3 junk + 1 capsule

        val data = "INNER_PACKET".toByteArray()
        val enc = hybrid.encapsulateData(data)
        val dec = hybrid.decapsulateData(enc)
        assertNotNull(dec)
        assertArrayEquals(data, dec)
    }

    @Test
    fun testMultiprotoProfileGateway() {
        val gw = MultiprotoProfileGateway()
        gw.registerEndpoint(AndroidGatewayEndpoint("ep1", ClientTunnelProtocol.AMNEZIA_WG, "1.1.1.1", 51820, 20, true))
        gw.registerEndpoint(AndroidGatewayEndpoint("ep2", ClientTunnelProtocol.MASQUE, "1.1.1.2", 443, 40, true))
        gw.setFailoverChain(listOf("ep1", "ep2"))

        assertEquals("ep1", gw.resolveActiveRoute()?.endpointId)

        gw.registerEndpoint(AndroidGatewayEndpoint("ep1", ClientTunnelProtocol.AMNEZIA_WG, "1.1.1.1", 51820, 20, false))
        assertEquals("ep2", gw.resolveActiveRoute()?.endpointId)
    }
}
