package com.luminet.android.tunnel

import org.junit.Assert.*
import org.junit.Test

class Batch8AndroidTest {

    @Test
    fun testSsrotStreamObfuscator() {
        val cfg = SsrotConfig("pass123", SsrotProtocolType.ORIGIN, SsrotObfsType.PLAIN)
        val client = SsrotStreamObfuscator(cfg)
        val server = SsrotStreamObfuscator(cfg)

        val hs = client.clientEncodeHandshake("test.host.com", 443, "ping".toByteArray())
        val (host, port, payload) = server.serverDecodeHandshake(hs)
        assertEquals("test.host.com", host)
        assertEquals(443, port)
        assertEquals("ping", String(payload))

        val chunk = client.encodeChunk("payload_chunk".toByteArray())
        val decoded = server.decodeChunk(chunk)
        assertEquals("payload_chunk", String(decoded))
    }

    @Test
    fun testReplayResistantTunnelSession() {
        val cfg = ReplayResistantConfig()
        val cRnd = "client_rnd".toByteArray()
        val sRnd = "server_rnd".toByteArray()

        val sender = ReplayResistantTunnelSession(cfg, cRnd, sRnd)
        val receiver = ReplayResistantTunnelSession(cfg, cRnd, sRnd)

        val now = 1700000000L
        val sealed = sender.sealPacket(1, now, "sensitive data".toByteArray())
        val (seq, ts, dec) = receiver.openPacket(sealed, now + 1)
        assertEquals(1L, seq)
        assertEquals(now, ts)
        assertEquals("sensitive data", String(dec))
    }

    @Test
    fun testMulticarrierRelayChannel() {
        val ch = MulticarrierRelayChannel()
        ch.addRoute(CarrierRoute(CarrierType.TELECOM, "1.1.1.1:443", 100, 0.05f, 100))
        ch.addRoute(CarrierRoute(CarrierType.UNICOM, "2.2.2.2:443", 40, 0.01f, 100))

        val best = ch.selectBestCarrier()
        assertNotNull(best)
        assertEquals(CarrierType.UNICOM, best!!.carrier)

        ch.recordFeedback(CarrierType.UNICOM, 999, false)
        ch.recordFeedback(CarrierType.UNICOM, 999, false)
        ch.recordFeedback(CarrierType.UNICOM, 999, false)

        val nextBest = ch.selectBestCarrier()
        assertEquals(CarrierType.TELECOM, nextBest!!.carrier)
    }

    @Test
    fun testNodePoolAggregator() {
        val agg = NodePoolAggregator()
        val lines = listOf(
            "ss://aes:pass@node1.org:8388",
            "trojan://sec@node2.org:443"
        )
        val count = agg.ingestRawEntries(lines, 1000L)
        assertEquals(2, count)

        agg.updateHealth("trojan:node2.org:443", 30, true)
        val ranked = agg.rankNodes(40.0)
        assertEquals(2, ranked.size)
        assertEquals("node2.org", ranked[0].host)
    }

    @Test
    fun testPacRuleGenerator() {
        val gen = PacRuleGenerator(PacRuleAction.DIRECT)
        gen.addRule("||google.com", PacRuleAction.PROXY, "127.0.0.1:1080")
        gen.addRule("|local.lan", PacRuleAction.DIRECT, "")

        val (act1, ep1) = gen.evaluateHost("news.google.com")
        assertEquals(PacRuleAction.PROXY, act1)
        assertEquals("127.0.0.1:1080", ep1)

        val (act2, _) = gen.evaluateHost("local.lan")
        assertEquals(PacRuleAction.DIRECT, act2)

        val script = gen.generatePacScript()
        assertTrue(script.contains("FindProxyForURL"))
    }

    @Test
    fun testMobileEngineProvider() {
        val prov = MobileEngineProvider(MobileEngineConfig())
        assertEquals(MobileEngineState.STOPPED, prov.state)

        prov.startEngine(1000L)
        assertEquals(MobileEngineState.RUNNING, prov.state)

        prov.recordTraffic(256, 512, 1030L)
        assertEquals(256L, prov.metrics.rxBytes)
        assertEquals(512L, prov.metrics.txBytes)
        assertEquals(30L, prov.metrics.uptimeSecs)

        prov.stopEngine()
        assertEquals(MobileEngineState.STOPPED, prov.state)
    }

    @Test
    fun testWireguardIpamManager() {
        val ipam = WireguardIpamManager("10.77.0", 51820)
        val p1 = ipam.allocatePeer("peer1_pubkey=")
        assertEquals("10.77.0.2", p1.assignedIp)

        val srvCfg = ipam.generateServerConfig("privkey=")
        assertTrue(srvCfg.contains("Address = 10.77.0.1/24"))

        val cliCfg = ipam.generateClientConfig("peer1_pubkey=", "cli_priv=", "srv_pub=", "1.2.3.4:51820")
        assertTrue(cliCfg.contains("Address = 10.77.0.2/32"))

        ipam.releasePeer("peer1_pubkey=")
    }

    @Test
    fun testSubscriptionHealthClassifier() {
        val cl = SubscriptionHealthClassifier(10)
        for (i in 0 until 10) {
            cl.recordSample("fast", 30, true)
            cl.recordSample("slow", 500, true)
        }
        assertEquals(HealthTier.TIER_A_EXCELLENT, cl.classifyNode("fast"))
        assertEquals(HealthTier.TIER_C_DEGRADED, cl.classifyNode("slow"))

        val usable = cl.filterUsableNodes(HealthTier.TIER_B_GOOD)
        assertEquals(listOf("fast"), usable)
    }

    @Test
    fun testPacDiffSynchronizer() {
        val sync = PacDiffSynchronizer(listOf("domain1.com", "domain2.com"))
        val delta = sync.computeDelta(listOf("domain1.com", "domain3.com"))

        assertEquals(listOf("domain3.com"), delta.addedDomains)
        assertEquals(listOf("domain2.com"), delta.removedDomains)

        val count = sync.applyDelta(delta)
        assertEquals(2, count)
        assertTrue(sync.containsRule("domain3.com"))
        assertFalse(sync.containsRule("domain2.com"))
    }

    @Test
    fun testDesktopClientManager() {
        val mgr = DesktopClientManager(7890, 7891)
        mgr.setProxyMode(SystemProxyMode.GLOBAL)
        assertEquals(SystemProxyMode.GLOBAL, mgr.mode)

        mgr.switchProfile("profile_ny")
        assertEquals("profile_ny", mgr.activeProfile)

        val st = mgr.getStatus()
        assertEquals("profile_ny", st.activeProfile)
    }

    @Test
    fun testSniSegmentationMasquerader() {
        val masq = SniSegmentationMasquerader(SniSegmentationStrategy.RANDOM_SPLIT, 4, 16)
        val testData = "0123456789abcdefghijklmnopqrstuvwxyz".toByteArray()
        val chunks = masq.segmentStream(testData, 999L)
        assertTrue(chunks.size > 1)

        val joined = ArrayList<Byte>()
        for (c in chunks) {
            for (b in c) joined.add(b)
        }
        assertArrayEquals(testData, joined.toByteArray())
    }

    @Test
    fun testSubscriptionCrawlerPipeline() {
        val pipe = SubscriptionCrawlerPipeline()
        pipe.addSource("https://subs.me", 3600L)

        val pending = pipe.dispatchPendingSources(1000L)
        assertEquals(1, pending.size)

        val raw = "vmess://uuid\ntrojan://pass@host:443"
        val ingested = pipe.ingestCrawlContent("https://subs.me", raw)
        assertEquals(2, ingested)
        assertEquals(2, pipe.totalHarvestedCount())
    }

    @Test
    fun testQuicStreamMultiplexer() {
        val mux = QuicStreamMultiplexer(65536)
        val s0 = mux.openStream(QuicStreamType.CLIENT_BIDIRECTIONAL)
        assertEquals(0L, s0)

        val f1 = mux.writeStreamData(s0, "Chunk 1 ".toByteArray(), false)
        val f2 = mux.writeStreamData(s0, "Chunk 2".toByteArray(), true)

        val receiver = QuicStreamMultiplexer(65536)
        val p2 = receiver.receiveStreamFrame(f2)
        assertEquals(0, p2.size)

        val p1 = receiver.receiveStreamFrame(f1)
        assertEquals("Chunk 1 Chunk 2", String(p1))
        assertTrue(receiver.isStreamClosed(s0))
    }

    @Test
    fun testQuicConnectionController() {
        val conn = QuicConnectionController(30000)
        conn.state = QuicConnectionState.ESTABLISHED
        assertTrue(conn.canSend(1000))

        conn.onPacketSent(1L, 1200, 1000L)
        assertEquals(1200L, conn.bytesInFlight)

        conn.onAckReceived(1L, 1040L)
        assertEquals(0L, conn.bytesInFlight)
        assertTrue(conn.calculatePtoMs() > 0)
    }

    @Test
    fun testQuicPacketCodec() {
        val codec = QuicPacketCodec()
        val encVar = codec.encodeVarint(1500L)
        val (decVar, len) = codec.decodeVarint(encVar, 0)
        assertEquals(1500L, decVar)
        assertEquals(encVar.size, len)

        val hdr = QuicPacketHeader(
            QuicHeaderType.ONE_RTT_SHORT,
            0L,
            byteArrayOf(1, 2, 3, 4),
            ByteArray(0),
            10L
        )
        val encoded = codec.encodePacket(hdr, "quic_payload".toByteArray())
        val (decHdr, decPayload) = codec.decodePacket(encoded, 4)
        assertEquals(QuicHeaderType.ONE_RTT_SHORT, decHdr.headerType)
        assertEquals(10L, decHdr.packetNumber)
        assertEquals("quic_payload", String(decPayload))
    }

    @Test
    fun testQuicEvasionTunnelCoordinator() {
        val dcid = byteArrayOf(1, 2, 3, 4)
        val scid = byteArrayOf(5, 6, 7, 8)
        val cRnd = "client_random".toByteArray()
        val sRnd = "server_random".toByteArray()

        val client = QuicEvasionTunnelCoordinator(dcid, scid, cRnd, sRnd, false)
        val server = QuicEvasionTunnelCoordinator(dcid, scid, cRnd, sRnd, false)

        val sid = client.openTunnelStream()
        val outbound = client.prepareOutboundDatagram(sid, "Test Evasion Tunnel".toByteArray(), 1000L)
        assertEquals(1, outbound.size)

        val (recvSid, payload) = server.processInboundDatagram(outbound[0], 1001L)
        assertEquals(sid, recvSid)
        assertEquals("Test Evasion Tunnel", String(payload))
    }

    @Test
    fun testPacSubscriptionOrchestrator() {
        val orch = PacSubscriptionOrchestrator(listOf("site1.com", "site2.com"), 10808)
        orch.registerSubscriptionSource("https://nodes.io", 3600L)

        val harvested = orch.executeCrawlAndIngest("https://nodes.io", "trojan://p@h:443", 1000L)
        assertEquals(1, harvested)

        orch.recordNodeProbe("trojan:h:443", 25, true)
        val summary = orch.getSummary()
        assertEquals(1, summary.totalCrawled)
        assertEquals(1, summary.usableTierACount)

        val delta = orch.updatePacWithUpstream(listOf("site1.com", "site3.com"))
        assertEquals(listOf("site3.com"), delta.addedDomains)
        assertTrue(orch.exportActivePacScript().contains("site3.com"))
    }
}
