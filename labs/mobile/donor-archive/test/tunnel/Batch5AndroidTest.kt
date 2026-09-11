package com.luminet.android.tunnel

import org.junit.Assert.*
import org.junit.Test

class Batch5AndroidTest {

    @Test
    fun test61_pacScriptCompiler() {
        val compiler = PacScriptCompiler("127.0.0.1:1080")
        compiler.addDirectDomain("baidu.com")
        compiler.addProxyDomain("google.com")

        assertEquals("DIRECT", compiler.evaluateDomain("baidu.com"))
        assertEquals("PROXY 127.0.0.1:1080", compiler.evaluateDomain("google.com"))
        assertTrue(compiler.compilePac().contains("PROXY 127.0.0.1:1080"))
    }

    @Test
    fun test62_dualBackendController() {
        val controller = DualBackendController()
        assertEquals(AndroidBackendEngine.KCP_RAW_SOCKET, controller.selectEngine())

        // 3 consecutive failures trigger failover
        controller.recordMetrics(AndroidBackendEngine.KCP_RAW_SOCKET, 300, 0.5f, false)
        controller.recordMetrics(AndroidBackendEngine.KCP_RAW_SOCKET, 300, 0.5f, false)
        controller.recordMetrics(AndroidBackendEngine.KCP_RAW_SOCKET, 300, 0.5f, false)

        assertEquals(AndroidBackendEngine.VIOLATED_TCP_QUIC, controller.selectEngine())
    }

    @Test
    fun test63_clashProviderSynthesizer() {
        val synth = ClashProviderSynthesizer(7890)
        synth.addNode(AndroidClashNode("US-01", "us.node.net", 443, "vless", "uuid-123"))
        synth.addGroup(AndroidClashGroup("ProxyGroup", "select", listOf("US-01")))

        val yaml = synth.synthesizeYaml()
        assertTrue(yaml.contains("mixed-port: 7890"))
        assertTrue(yaml.contains("name: \"US-01\""))
    }

    @Test
    fun test64_censorshipAnomalyProber() {
        val prober = CensorshipAnomalyProber()
        val rstSig = prober.probeTcpRst(true, 48, 56)
        assertNotNull(rstSig)
        assertEquals(AndroidCensorshipAnomaly.TCP_RST_INJECTION, rstSig?.anomaly)

        val dnsSig = prober.probeDnsPollution("blocked.org", listOf("127.0.0.1"))
        assertNotNull(dnsSig)
        assertEquals(AndroidCensorshipAnomaly.DNS_POLLUTION, dnsSig?.anomaly)
    }

    @Test
    fun test65_autoProxyRulesetMatcher() {
        val matcher = AutoProxyRulesetMatcher()
        matcher.parseLine("@@||cn.bing.com")
        matcher.parseLine("||google.com")

        assertEquals("DIRECT", matcher.match("https://cn.bing.com"))
        assertEquals("PROXY", matcher.match("https://google.com"))
        assertNull(matcher.match("https://unmatched.org"))
    }

    @Test
    fun test66_protocolCapabilityMatrix() {
        val matrix = ProtocolCapabilityMatrix()
        val rec = matrix.recommend(setOf("multipath_udp"))
        assertNotNull(rec)
        assertEquals("Hysteria2", rec?.name)
    }

    @Test
    fun test67_tcpWindowClamper() {
        val clamper = TcpWindowClamper(4)
        assertEquals(4, clamper.clampWindow(64240, true))
        assertEquals(64240, clamper.clampWindow(64240, false))
        assertTrue(clamper.isRstLegitimate(105000, 100000, 10000))
    }

    @Test
    fun test68_overTlsStreamCodec() {
        val codec = OverTlsStreamCodec(16)
        val data = "HELLO_OVERTLS".toByteArray()
        val encoded = codec.encode(data, 8)
        val decoded = codec.decode(encoded)
        assertNotNull(decoded)
        assertEquals("HELLO_OVERTLS", String(decoded!!))
    }

    @Test
    fun test69_dohFallbackHierarchy() {
        val hierarchy = DohFallbackHierarchy()
        val active = hierarchy.selectActive()
        assertNotNull(active)
        assertEquals(1, active?.tier)

        val url = active!!.url
        hierarchy.recordFailure(url)
        hierarchy.recordFailure(url)
        hierarchy.recordFailure(url)
        val next = hierarchy.selectActive()
        assertNotEquals(url, next?.url)
    }

    @Test
    fun test70_enterpriseAccessInterceptor() {
        val interceptor = EnterpriseAccessInterceptor()
        interceptor.protectRoute("/admin", AndroidUserRole.ADMIN)

        assertFalse(interceptor.authorize("/admin/users", AndroidUserRole.GUEST))
        assertTrue(interceptor.authorize("/admin/users", AndroidUserRole.ADMIN))
        assertEquals(2, interceptor.auditCount)
    }

    @Test
    fun test71_sniFragmentationInjector() {
        val injector = SniFragmentationInjector("microsoft.com")
        val frags = injector.splitInMiddle("SAMPLE_CLIENT_HELLO_BYTES".toByteArray())
        assertEquals(2, frags.size)

        val decoyPkts = injector.injectDecoy("REAL_PKT".toByteArray())
        assertEquals(2, decoyPkts.size)
    }

    @Test
    fun test72_routerOsRuleExporter() {
        val exporter = RouterOsRuleExporter()
        exporter.addEntry("1.1.1.0/24")
        val script = exporter.exportAddressList("gfw_list")
        assertTrue(script.contains("/ip firewall address-list"))
        assertTrue(script.contains("add list=gfw_list address=1.1.1.0/24"))
    }

    @Test
    fun test73_ebpfDnsDropFilter() {
        val filter = EbpfDnsDropFilter()
        assertFalse(filter.inspectPacket(0, 0, 53, ByteArray(12)))
        assertFalse(filter.inspectPacket(100, 0x0040, 53, ByteArray(12)))

        val valid = ByteArray(12)
        valid[7] = 2
        assertTrue(filter.inspectPacket(100, 0, 53, valid))
    }

    @Test
    fun test74_dynamicGatewayUpdater() {
        val updater = DynamicGatewayUpdater()
        updater.addRoute(AndroidGatewayRoute("1.1.1.1/32", "10.0.0.1", "tun0", 10))
        val cmds = updater.compileCommands()
        assertEquals(1, cmds.size)
        assertTrue(cmds[0].contains("1.1.1.1/32 via 10.0.0.1"))
    }

    @Test
    fun test75_singboxRulesetCompiler() {
        val compiler = SingboxRulesetCompiler()
        compiler.addRule("domain_suffix", "openai.com", "openai-out")
        assertEquals("openai-out", compiler.matchDomain("chat.openai.com"))
        assertTrue(compiler.exportJson().contains("\"openai-out\""))
    }

    @Test
    fun test76_autonomousRoutingCoordinator() {
        val coord = AutonomousRoutingCoordinator("Node-US")
        coord.autoProxy.parseLine("@@||cn.bing.com")
        coord.singbox.addRule("domain_suffix", "google.com", "proxy-direct")

        assertEquals("DIRECT", coord.evaluate("https://cn.bing.com"))
        assertEquals("PROXY proxy-direct", coord.evaluate("google.com"))
    }

    @Test
    fun test77_adaptiveProtocolMatrix() {
        val matrix = AdaptiveProtocolMatrix()
        val posture = matrix.adapt(AndroidCensorshipAnomaly.SNI_RESET)
        assertEquals("Trojan-SNI-Fragment", posture.recommendedProtocol)
        assertEquals(2, posture.windowClampSize)

        val postureUdp = matrix.adapt(AndroidCensorshipAnomaly.UDP_BLACKHOLE)
        assertEquals("VLESS-Reality", postureUdp.recommendedProtocol)
    }
}
