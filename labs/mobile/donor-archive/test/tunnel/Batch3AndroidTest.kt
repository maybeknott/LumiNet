package com.luminet.android.tunnel

import org.junit.Assert.*
import org.junit.Test

class Batch3AndroidTest {

    @Test
    fun test31_ednsSubnetScrubber() {
        val scrubber = EdnsSubnetScrubber(maskIpv4Bits = 24)
        assertEquals("192.168.1.0", scrubber.maskIpv4("192.168.1.100"))
        assertEquals("10.20.0.0", EdnsSubnetScrubber(maskIpv4Bits = 16).maskIpv4("10.20.30.40"))
    }

    @Test
    fun test32_httpChunkCarrier() {
        val carrier = HttpChunkCarrier("relay.luminet.io", "/tunnel", "sess-test")
        val hdr = String(carrier.createUplinkHeader(), Charsets.US_ASCII)
        assertTrue(hdr.startsWith("POST /tunnel HTTP/1.1"))

        val chunk = HttpChunkCarrier.encodeChunk("luminet-chunk".toByteArray())
        val decoded = HttpChunkCarrier.decodeChunk(chunk)
        assertNotNull(decoded)
        assertEquals("luminet-chunk", String(decoded!!.first))
    }

    @Test
    fun test33_edgeWorkerSelector() {
        val sel = EdgeWorkerSelector()
        sel.addOrUpdate("worker1.dev", "104.16.1.1", 443, 100, 0.0f)
        sel.addOrUpdate("worker2.dev", "104.16.2.2", 443, 80, 2.0f)
        sel.addOrUpdate("worker3.dev", "104.16.3.3", 443, 85, 0.0f)

        val best = sel.selectBest()
        assertNotNull(best)
        assertEquals("104.16.3.3", best!!.cleanIp)
        val uri = sel.synthesizeVlessUri(best, "uuid-x", "worker3.dev")
        assertTrue(uri.contains("104.16.3.3:443"))
    }

    @Test
    fun test34_adaptiveMtuDiscovery() {
        val disc = AdaptiveMtuDiscovery(1280, 1500)
        for (i in 0 until 10) {
            val probe = disc.nextProbeSize()
            val ok = probe <= 1420
            disc.recordResult(probe, ok)
            if (disc.convergedMtu != null) break
        }
        assertEquals(1420, disc.optimalMtu())
        assertEquals(1360, disc.wireguardPayloadMtu(false))
    }

    @Test
    fun test35_socketPoolSupervisor() {
        val pool = SocketPoolSupervisor()
        pool.registerSocket("s1", "1.1.1.1:443")
        pool.registerSocket("s2", "2.2.2.2:443")

        assertEquals("s1", pool.getActiveSocket()?.id)
        pool.recordHeartbeat("s1", 500, false)
        assertEquals("s2", pool.getActiveSocket()?.id)
    }

    @Test
    fun test36_proxyUriCodec() {
        val codec = ProxyUriCodec()
        val uri = "vless://test-uuid@myhost.net:443?encryption=none&security=tls#MyRemark"
        val parsed = codec.parse(uri)
        assertNotNull(parsed)
        assertEquals("vless", parsed!!.protocol)
        assertEquals("test-uuid", parsed.uuidOrPassword)
        assertEquals("myhost.net", parsed.address)
        assertEquals(443, parsed.port)

        val serialized = codec.serialize(parsed)
        assertTrue(serialized.contains("myhost.net:443"))
    }

    @Test
    fun test37_weightedEgressRouter() {
        val router = WeightedEgressRouter()
        router.addRoute("r1", "10.0.0.1:443", 3)
        router.addRoute("r2", "10.0.0.2:443", 1)

        val counts = mutableMapOf<String, Int>()
        for (i in 0 until 4) {
            val ep = router.nextRoute()!!
            counts[ep] = (counts[ep] ?: 0) + 1
        }
        assertEquals(3, counts["10.0.0.1:443"])
        assertEquals(1, counts["10.0.0.2:443"])
    }

    @Test
    fun test38_dpiPatternMasker() {
        val masker = DpiPatternMasker(5, true)
        val payload = byteArrayOf(0x16, 0x03, 0x01, 0x00, 0x50, 0x01, 0x00, 0x00, 0x4C)
        val frags = masker.fragmentPayload(payload)
        assertEquals(3, frags.size)

        val recomb = masker.reassemblePayload(frags)
        assertArrayEquals(payload, recomb)
    }

    @Test
    fun test39_tunRouteSynchronizer() {
        val sync = TunRouteSynchronizer(1400)
        assertTrue(sync.shouldBypass("192.168.1.1"))
        assertFalse(sync.shouldBypass("1.1.1.1"))
        assertEquals(1360, sync.calculateClampedMss(false))
        assertEquals(1340, sync.calculateClampedMss(true))
    }

    @Test
    fun test40_zeroRttSessionCache() {
        val cache = ZeroRttSessionCache()
        cache.storeTicket("edge.net", "ticket-data".toByteArray(), "h3", 1000, 300)
        assertNotNull(cache.getValidTicket("edge.net", 1100))
        assertNull(cache.getValidTicket("edge.net", 1400))

        val nonce = "nonce1".toByteArray()
        assertTrue(cache.checkAndConsumeNonce(nonce))
        assertFalse(cache.checkAndConsumeNonce(nonce))
    }

    @Test
    fun test41_packetFecEncoder() {
        val encoder = PacketFecEncoder(3)
        val p1 = "data1".toByteArray()
        val p2 = "data2".toByteArray()
        val p3 = "data3".toByteArray()

        val parity = encoder.computeParity(listOf(p1, p2, p3))
        val recovered = encoder.recoverSingleMissing(listOf(p1, p3), parity, p2.size)
        assertArrayEquals(p2, recovered)
    }

    @Test
    fun test42_multiFormatCompiler() {
        val comp = MultiFormatCompiler()
        val def = UnifiedOutboundDefinition(
            tag = "proxy1", protocol = "vless", server = "s.luminet.net",
            serverPort = 443, uuid = "u1", tlsSni = "s.luminet.net",
            transportType = "ws", wsPath = "/ws"
        )
        assertTrue(comp.compileSingBox(def).contains("vless"))
        assertTrue(comp.compileXray(def).contains("vnext"))
        assertTrue(comp.compileClash(def).contains("proxy1"))
    }

    @Test
    fun test43_covertStorageFramer() {
        val chunk = CovertChunk(1, 100L, false, "storage-data".toByteArray())
        val framed = CovertStorageFramer.frameChunk(chunk)
        val unframed = CovertStorageFramer.unframeChunk(framed)
        assertNotNull(unframed)
        assertEquals(chunk.streamId, unframed!!.streamId)
        assertEquals(chunk.sequence, unframed.sequence)
        assertArrayEquals(chunk.payload, unframed.payload)
    }

    @Test
    fun test44_multipathDedupBuffer() {
        val buf = MultipathDedupBuffer(1, 64)
        assertTrue(buf.ingest(2, "p2".toByteArray()).isEmpty())
        assertTrue(buf.ingest(2, "p2-dup".toByteArray()).isEmpty())
        val ready = buf.ingest(1, "p1".toByteArray())
        assertEquals(2, ready.size)
        assertEquals("p1", String(ready[0]))
        assertEquals("p2", String(ready[1]))
    }

    @Test
    fun test45_clientBanSupervisor() {
        val sup = ClientBanSupervisor(3, 60, 10.0, 1.0)
        val (dec, _) = sup.checkAccess("1.2.3.4", 100)
        assertEquals(AccessDecision.Allowed, dec)

        sup.recordAuthResult("1.2.3.4", false, 100)
        sup.recordAuthResult("1.2.3.4", false, 101)
        assertFalse(sup.isBanned("1.2.3.4", 101))

        sup.recordAuthResult("1.2.3.4", false, 102)
        assertTrue(sup.isBanned("1.2.3.4", 102))
    }
}
