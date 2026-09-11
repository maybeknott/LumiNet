package com.luminet.android.tunnel

import org.junit.Assert.*
import org.junit.Test

class Batch6AndroidTest {

    @Test
    fun testMultipathUdpTunnel() {
        val tunnel = MultipathUdpTunnel("tun-kt-01", BondingMode.ROUND_ROBIN)
        tunnel.addPath(PathMetrics(1, "127.0.0.1:8001", "10.0.0.1:9000", weight = 10))
        tunnel.addPath(PathMetrics(2, "127.0.0.1:8002", "10.0.0.1:9000", weight = 20))

        assertEquals(2, tunnel.activePaths().size)
        val p1 = tunnel.selectPathForEgress()
        val p2 = tunnel.selectPathForEgress()
        assertNotNull(p1)
        assertNotNull(p2)
        assertNotEquals(p1, p2)

        val payload = "android-multipath".toByteArray()
        val enc = tunnel.encapsulate(1, payload)
        assertNotNull(enc)
        val dec = tunnel.decapsulate(enc!!)
        assertNotNull(dec)
        assertEquals(1, dec!!.first)
        assertArrayEquals(payload, dec.second)
    }

    @Test
    fun testDnsBlocklistEngine() {
        val engine = DnsBlocklistEngine()
        engine.addExactRule("ad.tracking.com", BlockCategory.ADVERTISING)
        engine.addWildcardRule("evil-corp.net", BlockCategory.MALWARE)
        engine.addExactRule("clean.evil-corp.net", BlockCategory.MALWARE)
        engine.addWhitelist("clean.evil-corp.net")

        assertEquals(BlockCategory.ADVERTISING, engine.isDomainBlocked("ad.tracking.com"))
        assertEquals(BlockCategory.MALWARE, engine.isDomainBlocked("sub.evil-corp.net"))
        assertNull(engine.isDomainBlocked("clean.evil-corp.net"))
        assertNull(engine.isDomainBlocked("safe.org"))
    }

    @Test
    fun testZeroCopyNetworkRelay() {
        val relay = ZeroCopyNetworkRelay(8443, ProxyProtocolVersion.V1)
        relay.addEndpoint(RelayEndpoint("10.0.0.1", 443))
        relay.addEndpoint(RelayEndpoint("10.0.0.2", 443))

        val session1 = relay.openSession()
        assertNotNull(session1)
        val session2 = relay.openSession()
        assertNotNull(session2)
        assertNotEquals(session1!!.second.targetHost, session2!!.second.targetHost)

        val header = String(relay.generateProxyHeader("192.168.1.5", 12345, "10.0.0.1", 443))
        assertTrue(header.startsWith("PROXY TCP4 192.168.1.5 10.0.0.1 12345 443"))
        relay.closeSession(session1.first, 1024)
    }

    @Test
    fun testEmbeddedProbeServer() {
        val server = EmbeddedProbeServer("127.0.0.1", 8080)
        server.setAuth("admin", "secret123")
        server.registerPayload("/test.bin", "hello world".toByteArray())

        val unauth = server.handleRequest("GET", "/health", null, null)
        assertEquals(401, unauth.statusCode)

        val authOk = server.handleRequest("GET", "/health", "Basic admin:secret123", null)
        assertEquals(200, authOk.statusCode)

        val rangeRes = server.handleRequest("GET", "/test.bin", "Basic admin:secret123", "bytes=0-4")
        assertEquals(206, rangeRes.statusCode)
        assertEquals("hello", String(rangeRes.body))
    }

    @Test
    fun testFlowAnalyzerEngine() {
        val engine = FlowAnalyzerEngine()
        val tlsHello = byteArrayOf(0x16, 0x03, 0x01, 0x00, 0x50)
        val fid = engine.registerFlow("192.168.1.20:50000", "1.1.1.1:443", tlsHello)

        val flow = engine.getFlow(fid)
        assertNotNull(flow)
        assertEquals(FlowProtocol.TLS, flow!!.protocol)

        engine.recordPacket(fid, 1000, isEgress = true, isRetransmission = true)
        engine.recordPacket(fid, 1000, isEgress = true, isRetransmission = true)
        val anomalies = engine.detectAnomalies(50.0)
        assertTrue(anomalies.contains(fid))
    }

    @Test
    fun testMitmTrafficRewriter() {
        val rewriter = MitmTrafficRewriter()
        rewriter.addRule(
            AndroidRewriteRule(
                ruleId = "r1",
                domainPattern = "api.service.com",
                pathPrefix = "/auth",
                action = AndroidRewriteAction.SetHeader("X-Lumi-Rewritten", "true")
            )
        )
        val headers = mutableMapOf<String, String>()
        val (path, action) = rewriter.rewriteRequest("api.service.com", "/auth/login", headers)
        assertEquals("/auth/login", path)
        assertNotNull(action)
        assertEquals("true", headers["X-Lumi-Rewritten"])
    }

    @Test
    fun testCanonicalBlacklistEngine() {
        val engine = CanonicalBlacklistEngine()
        engine.parseRawRule("||bad-domain.org")
        engine.parseRawRule("@@||good.bad-domain.org")

        val (v1, rule1) = engine.evaluateTarget("bad-domain.org")
        assertEquals(BlacklistMatchVerdict.BLOCKED, v1)
        assertEquals("bad-domain.org", rule1)

        val (v2, _) = engine.evaluateTarget("good.bad-domain.org")
        assertEquals(BlacklistMatchVerdict.WHITELISTED, v2)

        val (v3, _) = engine.evaluateTarget("random.com")
        assertEquals(BlacklistMatchVerdict.DIRECT, v3)
    }

    @Test
    fun testNfqueuePacketScrambler() {
        val scrambler = NfqueuePacketScrambler(1, 0xCAFE)
        val packet = ByteArray(40)
        packet[0] = 0x45
        packet[8] = 128.toByte()
        packet[9] = 6 // TCP
        packet[20 + 13] = 0x12 // SYN+ACK

        val act = scrambler.processIpPacket("8.8.8.8", packet)
        assertEquals(AndroidScrambleAction.ALTER_TTL, act)
        assertEquals(64.toByte(), packet[8])

        scrambler.addShortcut("8.8.8.8", 10000)
        val act2 = scrambler.processIpPacket("8.8.8.8", packet)
        assertEquals(AndroidScrambleAction.MARK_PACKET, act2)
    }

    @Test
    fun testPrivoxyActionGenerator() {
        val gen = PrivoxyActionGenerator("127.0.0.1:10808")
        gen.addForwardDomain("blocked.org")
        gen.addDirectBypass("intranet.local")

        val file = gen.generateActionFile()
        assertTrue(file.contains("{-forward-override}\n.intranet.local"))
        assertTrue(file.contains("{+forward-override{forward-socks5 127.0.0.1:10808 .}}\n.blocked.org"))
    }

    @Test
    fun testGeospatialPolygonRouter() {
        val router = GeospatialPolygonRouter("direct")
        val poly = listOf(
            AndroidGeoPoint(10.0, 10.0),
            AndroidGeoPoint(20.0, 10.0),
            AndroidGeoPoint(15.0, 20.0)
        )
        router.addRegion(AndroidGeoRegion("REG-A", "Region A", poly, "proxy-a"))

        val inside = AndroidGeoPoint(15.0, 12.0)
        val outside = AndroidGeoPoint(5.0, 5.0)

        assertEquals(Pair("proxy-a", "REG-A"), router.resolveEgress(inside))
        assertEquals(Pair("direct", null), router.resolveEgress(outside))
    }

    @Test
    fun testSniHostnameRewriter() {
        val rewriter = SniHostnameRewriter()
        rewriter.addSniRule("pixiv.net", "app.pixiv.net", listOf("*.pixiv.net"))
        rewriter.addHttpRedirect("wiki.org", "wikipedia.org")

        val (sni, rule) = rewriter.resolveSni("pixiv.net")
        assertEquals("app.pixiv.net", sni)
        assertNotNull(rule)
        assertTrue(rewriter.checkSanValidity(rule!!, listOf("img.pixiv.net")))

        assertEquals("https://wikipedia.org", rewriter.checkHttpRedirect("wiki.org/page"))
    }

    @Test
    fun testPoisonedDnsResponseFilter() {
        val filter = PoisonedDnsResponseFilter()
        val bogus = "74.125.127.102"
        val good = "1.1.1.1"

        val clean = filter.filterIps(listOf(bogus, good))
        assertEquals(listOf(good), clean)
        assertEquals(1L, filter.droppedCount)
        assertEquals(1L, filter.acceptedCount)
    }

    @Test
    fun testAutomatedTlsServerConfigurator() {
        val conf = AutomatedTlsServerConfigurator()
        conf.registerServer(
            "srv1",
            AndroidServerConfig(
                passwords = listOf("pw1"),
                tls = AndroidTlsBinding("/cert.pem", "/key.pem", "edge.org")
            )
        )
        val json = conf.generateJsonConfig("srv1")
        assertNotNull(json)
        assertTrue(json!!.contains("\"run_type\": \"server\""))
        assertTrue(json.contains("\"pw1\""))
    }

    @Test
    fun testToolchainProxyWrapper() {
        val wrapper = ToolchainProxyWrapper("http://127.0.0.1:8080", "socks5://127.0.0.1:1080")
        val git = wrapper.generateSnippet(AndroidToolchainTarget.GIT)
        assertTrue(git.contains("proxy = http://127.0.0.1:8080"))

        val env = wrapper.generateEnvVars()
        assertEquals("socks5://127.0.0.1:1080", env["ALL_PROXY"])
    }

    @Test
    fun testCensorshipProfileSynthesizer() {
        val synth = CensorshipProfileSynthesizer()
        val iran = synth.getProfile(AndroidCensorshipRegion.IRAN)
        assertTrue(iran.dnsFragmentationEnabled)
        assertEquals(32, iran.dnsFragmentSize)

        val global = synth.getProfile(AndroidCensorshipRegion.GLOBAL)
        assertFalse(global.dnsFragmentationEnabled)
    }

    @Test
    fun testMultipathEvasionPipeline() {
        val pipe = MultipathEvasionPipeline("pipe-kt", BondingMode.ROUND_ROBIN, 1, 0xCAFE, AndroidCensorshipRegion.CHINA)
        pipe.registerPath(1, "127.0.0.1:7001", "10.0.0.1:8000", 10)

        val payload = ByteArray(40) { 0x45 }
        val out = pipe.prepareOutboundPacket("1.1.1.1", payload)
        assertNotNull(out)
        assertEquals(1, out!!.first)
        assertTrue(out.second.size > payload.size)
    }

    @Test
    fun testIntelligentTrafficFilter() {
        val filter = IntelligentTrafficFilter("direct")
        filter.dnsBlocklist.addExactRule("track.ad.com", BlockCategory.TRACKING)
        filter.canonicalBlacklist.parseRawRule("||proxy-site.net")

        val v1 = filter.evaluateTraffic("127.0.0.1:1000", "1.2.3.4:443", "track.ad.com", null, byteArrayOf())
        assertTrue(v1 is AndroidFilterVerdict.BlockedDns)

        val v2 = filter.evaluateTraffic("127.0.0.1:1000", "1.2.3.4:443", "proxy-site.net", null, byteArrayOf())
        assertTrue(v2 is AndroidFilterVerdict.ProxyRequired)

        val v3 = filter.evaluateTraffic("127.0.0.1:1000", "1.2.3.4:443", "clean.com", null, byteArrayOf())
        assertTrue(v3 is AndroidFilterVerdict.DirectPassThrough)
    }
}
