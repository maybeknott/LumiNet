package com.luminet.android.tunnel

import org.junit.Assert.*
import org.junit.Test
import java.nio.charset.StandardCharsets

class Batch1AndroidTest {

    @Test
    fun testCdnFrontPool() {
        val pool = CdnFrontPool()
        assertTrue(pool.addCandidate("192.0.2.1", "front.example.com", 443))
        assertTrue(pool.addCandidate("192.0.2.2", "front2.example.com", 443))
        val best = pool.selectBest()
        assertNotNull(best)
        best?.recordSuccess(25.0)
        assertEquals(25.0, best?.rttEmaMs ?: 0.0, 0.01)
    }

    @Test
    fun testIpsecTunnelProfile() {
        val profile = IpsecProfile.create("203.0.113.1", "client@internal", "server@internal")
        val conf = profile.generateSwanctlConf()
        assertTrue(conf.contains("203.0.113.1"))
        assertTrue(conf.contains("client@internal"))
    }

    @Test
    fun testWireguardPeerAllocator() {
        val allocator = WireguardPeerAllocator()
        val p1 = allocator.allocatePeer("pubkey111=", "peer1")
        assertEquals("10.88.0.2", p1.allocatedIpv4)
        val conf = allocator.formatClientConfig(p1, "privKey==", "vpn.net:51820", "srvPubKey==")
        assertTrue(conf.contains("Address = 10.88.0.2/32"))
    }

    @Test
    fun testIdentityTunnelCodec() {
        val token = ByteArray(32) { it.toByte() }
        val encoded = IdentityTunnelCodec.encode(8443, token, "app.internal")
        val decoded = IdentityTunnelCodec.decode(encoded)
        assertNotNull(decoded)
        assertEquals(8443, decoded?.targetPort)
        assertEquals("app.internal", decoded?.targetDomain)
    }

    @Test
    fun testBrutalPacerAndSalamander() {
        val pacer = BrutalPacer(10_000_000L)
        val rate = pacer.updateAckFeedback(10_000_000L, 0.20)
        assertEquals(12_000_000L, rate)

        val key = ByteArray(32) { (it * 3).toByte() }
        val enc = SalamanderObfuscator(key)
        val dec = SalamanderObfuscator(key)
        val original = "Test payload string".toByteArray(StandardCharsets.UTF_8)
        val buf = original.copyOf()
        enc.applyInPlace(buf)
        assertFalse(buf.contentEquals(original))
        dec.applyInPlace(buf)
        assertTrue(buf.contentEquals(original))
    }

    @Test
    fun testVirtualEthernetSwitch() {
        val sw = VirtualEthernetSwitch()
        sw.learn("0102030405", "10.0.0.1:9993")
        assertEquals("10.0.0.1:9993", sw.lookup("0102030405"))

        val src = byteArrayOf(1, 2, 3, 4, 5)
        val dst = byteArrayOf(6, 7, 8, 9, 10)
        val frame = SwitchPacketFrame(src, dst, 0x0800, byteArrayOf(1, 1, 1))
        val enc = frame.encode()
        val dec = SwitchPacketFrame.decode(enc)
        assertNotNull(dec)
        assertTrue(dec?.source?.contentEquals(src) == true)
    }

    @Test
    fun testMultipathFallbackRouter() {
        val router = MultipathFallbackRouter()
        assertEquals(FallbackTierType.DIRECT, router.selectActiveTier())
        router.recordFailure(FallbackTierType.DIRECT)
        router.recordFailure(FallbackTierType.DIRECT)
        assertEquals(FallbackTierType.DOMAIN_FRONTED, router.selectActiveTier())
    }

    @Test
    fun testFirewallKillswitch() {
        val ks = KillswitchRules(vpnServerIp = "198.51.100.1")
        val rules = ks.generateIptablesRules()
        assertTrue(rules.any { it.contains("-P OUTPUT DROP") })
        assertTrue(rules.any { it.contains("198.51.100.1") })
    }

    @Test
    fun testBrookStreamCodec() {
        val req = BrookRequest(BrookTargetType.DOMAIN, "api.luminet.internal", 443)
        val encoded = BrookStreamCodec.encodeRequest(req)
        val decoded = BrookStreamCodec.decodeRequest(encoded)
        assertNotNull(decoded)
        assertEquals("api.luminet.internal", decoded?.host)
        assertEquals(443, decoded?.port)
    }

    @Test
    fun testSslVpnStream() {
        val frame = SslVpnFrame(0x1234, byteArrayOf(10, 20, 30))
        val encoded = frame.encode()
        val decoded = SslVpnFrame.decode(encoded)
        assertNotNull(decoded)
        assertEquals(0x1234, decoded?.sessionId)
        assertTrue(decoded?.payload?.contentEquals(byteArrayOf(10, 20, 30)) == true)
    }

    @Test
    fun testTransparentChannelMux() {
        val frame = ChannelMuxFrame(42, ChannelOpcode.CHANNEL_DATA, byteArrayOf(1, 2, 3, 4))
        val encoded = frame.encode()
        val decoded = ChannelMuxFrame.decode(encoded)
        assertNotNull(decoded)
        assertEquals(42, decoded?.channelId)
        assertEquals(ChannelOpcode.CHANNEL_DATA, decoded?.opcode)
    }

    @Test
    fun testMeshPeerRoute() {
        val mesh = MeshPeerTable()
        mesh.recordLink("A", "B", 10.0, 0.0, 1)
        mesh.recordLink("B", "C", 10.0, 0.0, 1)
        mesh.recordLink("A", "C", 100.0, 0.5, 1)

        val route = mesh.findBestRoute("A", "C")
        assertNotNull(route)
        assertEquals("B", route?.first)
    }

    @Test
    fun testPeerAclMatrix() {
        val matrix = PeerAclMatrix(defaultAllow = true)
        matrix.setRule("client1", "server1", false)
        assertFalse(matrix.isAllowed("client1", "server1"))
        assertTrue(matrix.isAllowed("client1", "server2"))
    }

    @Test
    fun testKernelHardeningAuditor() {
        val auditor = KernelHardeningAuditor()
        val map = mapOf(
            "net.ipv4.ip_forward" to "1",
            "net.ipv4.conf.all.rp_filter" to "1",
            "net.ipv4.conf.default.rp_filter" to "1",
            "net.ipv4.conf.all.accept_source_route" to "0",
            "net.ipv4.tcp_syncookies" to "1"
        )
        val score = auditor.audit(map)
        assertEquals(100.0, score, 0.01)
    }

    @Test
    fun testWarpAccountClient() {
        val prof = WarpProfile("acc1", "token1", "privKey111=")
        val conf = WarpAccountClient.synthesizeWireguardConf(prof)
        assertTrue(conf.contains("PrivateKey = privKey111="))
        assertTrue(conf.contains("engage.cloudflareclient.com:2408"))
    }
}
