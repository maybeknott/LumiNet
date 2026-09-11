package com.luminet.android.tunnel

import org.junit.Assert.*
import org.junit.Test
import java.util.Base64

class Batch7AndroidTest {

    @Test
    fun testEdgeGatewayHealthMeter() {
        val meter = EdgeGatewayHealthMeter(300)
        meter.recordProbe("gw1.net:443", 120, true, 2)
        meter.recordProbe("gw2.net:443", 400, true, 1) // exceeds 300ms threshold
        meter.recordProbe("gw3.net:443", 50, false, 0) // failed probe

        val m1 = meter.getMetric("gw1.net:443")
        assertNotNull(m1)
        assertTrue(m1!!.isHealthy)
        assertEquals(120L, m1.rttMs)

        val m2 = meter.getMetric("gw2.net:443")
        assertFalse(m2!!.isHealthy)

        val healthy = meter.healthyGateways()
        assertEquals(1, healthy.size)
        assertEquals("gw1.net:443", healthy[0])

        assertEquals("gw1.net:443", meter.selectBestGateway())
    }

    @Test
    fun testSubscriptionNodeExtractor() {
        val extractor = SubscriptionNodeExtractor()
        val plain = "trojan://password123@trojan.example.com:443#Trojan-US\nss://YWVzLTEyOC1nY206cGFzc3dvcmQ@ss.example.com:8388#SS-HK\n"
        val b64 = Base64.getEncoder().encodeToString(plain.toByteArray(Charsets.UTF_8))

        val nodes = extractor.decodeSubscription(b64)
        assertEquals(2, nodes.size)
        assertEquals(AndroidProxyType.TROJAN, nodes[0].nodeType)
        assertEquals("trojan.example.com", nodes[0].address)
        assertEquals(443, nodes[0].port)
        assertEquals("Trojan-US", nodes[0].remark)

        assertEquals(AndroidProxyType.SHADOWSOCKS, nodes[1].nodeType)
        assertEquals("ss.example.com", nodes[1].address)
        assertEquals(8388, nodes[1].port)
        assertEquals("SS-HK", nodes[1].remark)
    }

    @Test
    fun testMobileTunnelSupervisor() {
        val config = MobileSupervisorConfig(
            splitMode = SplitTunnelMode.EXCLUDE_PACKAGES,
            packages = setOf("com.bypass.app"),
            primaryDns = "1.1.1.1",
            fallbackDns = "8.8.8.8",
            autoReconnect = true
        )
        val supervisor = MobileTunnelSupervisor(config)
        assertEquals(AndroidTunnelState.DISCONNECTED, supervisor.state)

        supervisor.startTunnel()
        assertEquals(AndroidTunnelState.CONNECTED, supervisor.state)

        assertTrue(supervisor.isAppRouted("com.browser.app"))
        assertFalse(supervisor.isAppRouted("com.bypass.app"))

        supervisor.handleNetworkDrop()
        assertEquals(AndroidTunnelState.RECONNECTING, supervisor.state)
        assertEquals(1, supervisor.getReconnectAttempts())

        assertEquals("1.1.1.1", supervisor.getEffectiveDns(false))
        assertEquals("8.8.8.8", supervisor.getEffectiveDns(true))

        supervisor.stopTunnel()
        assertEquals(AndroidTunnelState.STOPPED, supervisor.state)
    }

    @Test
    fun testMultiOutboundRouter() {
        val router = MultiOutboundRouter(AndroidOutboundPolicy.Direct)
        router.addRule("internal.corp", true, AndroidOutboundPolicy.Direct)
        router.addRule("blocked.com", false, AndroidOutboundPolicy.Proxy("us-node"))
        router.addRule("malware.net", true, AndroidOutboundPolicy.Reject)

        assertEquals(AndroidOutboundPolicy.Direct, router.matchTarget("app.internal.corp"))
        assertEquals(AndroidOutboundPolicy.Proxy("us-node"), router.matchTarget("blocked.com"))
        assertEquals(AndroidOutboundPolicy.Reject, router.matchTarget("bad.malware.net"))
        assertEquals(AndroidOutboundPolicy.Direct, router.matchTarget("random.org"))

        val nodes = listOf("node1", "node2")
        val s1 = router.selectBalancedOutbound(nodes)
        val s2 = router.selectBalancedOutbound(nodes)
        assertNotNull(s1)
        assertNotNull(s2)
        assertNotEquals(s1, s2)
    }

    @Test
    fun testProviderFailoverWatcher() {
        val watcher = ProviderFailoverWatcher(2)
        watcher.registerProvider("prov1", true)
        watcher.registerProvider("prov2", false)

        assertEquals("prov1", watcher.activeProvider)

        watcher.recordHeartbeat("prov1", 50, false)
        assertEquals(AndroidProviderStatus.UNSTABLE, watcher.getHealth("prov1")?.status)
        assertEquals("prov1", watcher.activeProvider)

        val failover = watcher.recordHeartbeat("prov1", 50, false)
        assertEquals("prov2", failover)
        assertEquals("prov2", watcher.activeProvider)
        assertEquals(AndroidProviderStatus.FAILED, watcher.getHealth("prov1")?.status)
    }

    @Test
    fun testCompositeRuleCompiler() {
        val compiler = CompositeRuleCompiler()
        assertTrue(compiler.parseLine("DOMAIN-SUFFIX,google.com,PROXY"))
        assertTrue(compiler.parseLine("DOMAIN,netflix.com,DIRECT"))
        assertTrue(compiler.parseLine("IP-CIDR,192.168.0.0/16,DIRECT"))
        assertTrue(compiler.parseLine("IP-CIDR,10.0.0.0/8,REJECT"))

        assertEquals(AndroidRuleAction.PROXY, compiler.evaluateDomain("maps.google.com"))
        assertEquals(AndroidRuleAction.DIRECT, compiler.evaluateDomain("netflix.com"))
        assertNull(compiler.evaluateDomain("other.org"))

        assertEquals(AndroidRuleAction.DIRECT, compiler.evaluateIp("192.168.1.100"))
        assertEquals(AndroidRuleAction.REJECT, compiler.evaluateIp("10.1.2.3"))
        assertNull(compiler.evaluateIp("8.8.8.8"))
    }

    @Test
    fun testEnhancedGeoIpLookup() {
        val lookup = EnhancedGeoIpLookup()
        lookup.addCidr("1.0.1.0", 24, "CN")
        lookup.addCidr("8.8.8.0", 24, "US")
        lookup.addCidr("8.8.0.0", 16, "US-BROAD")

        assertEquals("CN", lookup.lookup("1.0.1.55"))
        assertEquals("US", lookup.lookup("8.8.8.8"))
        assertEquals("US-BROAD", lookup.lookup("8.8.10.1"))
        assertNull(lookup.lookup("9.9.9.9"))

        assertTrue(EnhancedGeoIpLookup.isPrivate("192.168.1.1"))
        assertTrue(EnhancedGeoIpLookup.isPrivate("10.0.0.1"))
        assertFalse(EnhancedGeoIpLookup.isPrivate("8.8.8.8"))
    }

    @Test
    fun testEndpointCredentialVault() {
        val key = ByteArray(32) { 0x42.toByte() }
        val vault = EndpointCredentialVault(key)
        val secret = "my-vpn-key".toByteArray(Charsets.UTF_8)

        vault.storeProfile("prof1", "vpn.net", 443, "user", secret, 1000L, 300L)
        assertTrue(vault.isProfileValid("prof1", 1100L))

        val retrieved = vault.retrieveSecret("prof1", 1100L)
        assertNotNull(retrieved)
        assertArrayEquals(secret, retrieved)

        assertFalse(vault.isProfileValid("prof1", 1301L))
        assertNull(vault.retrieveSecret("prof1", 1301L))

        assertEquals(1, vault.purgeExpired(1301L))
        assertFalse(vault.isProfileValid("prof1", 1100L))
    }

    @Test
    fun testCamouflageStreamMasquerader() {
        val secret = "camou-secret-seed".toByteArray(Charsets.UTF_8)
        val masq = CamouflageStreamMasquerader(secret, "www.microsoft.com")
        val uid = ByteArray(16) { it.toByte() }
        masq.registerUser(uid)

        val preamble = masq.generatePreamble(uid)
        assertEquals(AndroidProbeAction.ACCEPT_STREAM, masq.inspectInboundStream(preamble))

        val invalid = ByteArray(32)
        assertEquals(AndroidProbeAction.DEFLECT_TO_DECOY, masq.inspectInboundStream(invalid))
        assertEquals("www.microsoft.com", masq.decoyHost)
    }

    @Test
    fun testProgrammableProxyPipeline() {
        val pipeline = ProgrammableProxyPipeline()
        pipeline.addHook(AndroidHeaderInjectorHook("X-Client", "LumiAndroid"))
        pipeline.addHook(AndroidBlockPathHook("/admin/secret"))

        val headers = mutableListOf("Host" to "api.corp")
        val (code1, _) = pipeline.processRequest("GET", "/public/feed", headers)
        assertEquals(200, code1)
        assertTrue(headers.any { it.first == "X-Client" && it.second == "LumiAndroid" })

        val badHeaders = mutableListOf<Pair<String, String>>()
        val (code2, body2) = pipeline.processRequest("GET", "/admin/secret/data", badHeaders)
        assertEquals(403, code2)
        assertNotNull(body2)
        assertTrue(String(body2!!).contains("Forbidden"))
    }

    @Test
    fun testEdgeCdnPoolSorter() {
        val sorter = EdgeCdnPoolSorter(300L)
        sorter.addIp("142.250.190.46")
        sorter.addIp("172.217.16.206")
        sorter.addIp("216.58.214.206")

        sorter.updateProbeResult("142.250.190.46", 120L, true)
        sorter.updateProbeResult("172.217.16.206", 45L, true)
        sorter.updateProbeResult("216.58.214.206", 450L, true) // exceeds 300ms

        assertEquals("172.217.16.206", sorter.bestIp())
        val sorted = sorter.getSortedFastest()
        assertEquals(2, sorted.size)
        assertEquals(45L, sorted[0].latencyMs)
        assertEquals(120L, sorted[1].latencyMs)
    }

    @Test
    fun testNodeIngestDeduplicator() {
        val dedup = NodeIngestDeduplicator()
        val n1 = AndroidScrapedNode("node1.net", 443, "trojan", "feed_a", 150L, true)
        val n2 = AndroidScrapedNode("NODE1.NET", 443, "trojan", "feed_b", 180L, true)
        val n3 = AndroidScrapedNode("node2.net", 8443, "vmess", "feed_a", 60L, true)

        assertTrue(dedup.ingestNode(n1))
        assertFalse(dedup.ingestNode(n2)) // duplicate
        assertTrue(dedup.ingestNode(n3))

        assertEquals(2, dedup.totalUnique())
        assertEquals(2, dedup.countForSource("feed_a"))
        assertEquals(0, dedup.countForSource("feed_b"))

        val ranked = dedup.getRankedNodes()
        assertEquals(2, ranked.size)
        assertEquals("node2.net", ranked[0].host)
    }

    @Test
    fun testSessionRotationPool() {
        val pool = SessionRotationPool(60L)
        pool.addAccount("acc1", "token1", 2)
        pool.addAccount("acc2", "token2", 1)

        val p1 = pool.acquireAccount(100L)
        assertEquals("acc1", p1?.first)

        val p2 = pool.acquireAccount(100L)
        assertEquals("acc2", p2?.first)

        val p3 = pool.acquireAccount(100L)
        assertEquals("acc1", p3?.first)

        assertNull(pool.acquireAccount(100L)) // both in cooldown

        val p4 = pool.acquireAccount(161L)
        assertNotNull(p4)
    }

    @Test
    fun testCensorshipTriggerGenerator() {
        val gen = CensorshipTriggerGenerator()
        assertTrue(gen.totalProbes() >= 4)

        val sni = gen.getProbesByCategory(AndroidProbeCategory.SNI_PATTERN)
        assertFalse(sni.isEmpty())
        assertEquals("zh.wikipedia.org", sni[0].payloadString)

        val probe = gen.generateHttpProbe("zh.wikipedia.org", "/wiki/Test")
        val probeStr = String(probe, Charsets.UTF_8)
        assertTrue(probeStr.contains("Host: zh.wikipedia.org"))
        assertTrue(probeStr.contains("GET /wiki/Test HTTP/1.1"))
    }

    @Test
    fun testPolicyRulesetRouter() {
        val router = PolicyRulesetRouter(AndroidPolicyVerdict.DIRECT)
        router.addExactDomain("ads.google.com", AndroidPolicyVerdict.REJECT)
        router.addSuffixDomain("google.com", AndroidPolicyVerdict.PROXY)
        router.addKeyword("telegram", AndroidPolicyVerdict.PROXY)
        router.addCidr("10.0.0.0", 8, AndroidPolicyVerdict.DIRECT)

        assertEquals(AndroidPolicyVerdict.REJECT, router.resolveDomain("ads.google.com"))
        assertEquals(AndroidPolicyVerdict.PROXY, router.resolveDomain("mail.google.com"))
        assertEquals(AndroidPolicyVerdict.PROXY, router.resolveDomain("telegram.org"))
        assertEquals(AndroidPolicyVerdict.DIRECT, router.resolveDomain("wikipedia.org"))

        assertEquals(AndroidPolicyVerdict.DIRECT, router.resolveIp("10.1.2.3"))
        assertEquals(AndroidPolicyVerdict.DIRECT, router.resolveIp("1.1.1.1"))
    }

    @Test
    fun testAdaptiveOutboundCoordinator() {
        val coord = AdaptiveOutboundCoordinator(
            defaultPolicy = AndroidOutboundPolicy.Direct,
            failoverThreshold = 3,
            sharedSecret = "secret-123".toByteArray(Charsets.UTF_8),
            decoyHost = "www.cloudflare.com",
            maxCdnLatency = 200L
        )

        coord.router.addRule("blocked.org", true, AndroidOutboundPolicy.Proxy("proxy-us"))
        coord.cdnSorter.addIp("104.16.1.1")
        coord.cdnSorter.updateProbeResult("104.16.1.1", 35L, true)

        val uid = ByteArray(16) { 0x77.toByte() }
        coord.masquerader.registerUser(uid)

        val (policy, ip, preamble) = coord.routeAndPrepareOutbound("sub.blocked.org", uid)
        assertEquals(AndroidOutboundPolicy.Proxy("proxy-us"), policy)
        assertEquals("104.16.1.1", ip)
        assertEquals(AndroidProbeAction.ACCEPT_STREAM, coord.handleInboundProbe(preamble))
    }

    @Test
    fun testAutonomousIngestPipeline() {
        val pipeline = AutonomousIngestPipeline(AndroidPolicyVerdict.DIRECT)
        pipeline.geoip.addCidr("223.5.5.0", 24, "CN")
        pipeline.ruleCompiler.parseLine("DOMAIN-SUFFIX,google.com,PROXY")
        pipeline.ruleCompiler.parseLine("DOMAIN-SUFFIX,ads.evil.com,REJECT")

        assertEquals(AndroidPolicyVerdict.DIRECT, pipeline.evaluateEgress("some-cn-site.cn", "223.5.5.5"))
        assertEquals(AndroidPolicyVerdict.PROXY, pipeline.evaluateEgress("mail.google.com"))
        assertEquals(AndroidPolicyVerdict.REJECT, pipeline.evaluateEgress("tracker.ads.evil.com"))
    }
}
