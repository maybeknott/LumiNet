package com.luminet.android.tunnel

import org.junit.Assert.assertEquals
import org.junit.Assert.assertNotNull
import org.junit.Assert.assertTrue
import org.junit.Test
import java.nio.charset.StandardCharsets

class MultiStrategyFragmenterTest {

    private fun buildTestClientHello(sniHost: String): ByteArray {
        val hostBytes = sniHost.toByteArray(StandardCharsets.US_ASCII)
        val pkt = mutableListOf<Byte>()

        // TLS Record Header: Handshake (0x16), TLS 1.0 (0x03, 0x01), Length placeholder
        pkt.addAll(listOf(0x16.toByte(), 0x03.toByte(), 0x01.toByte(), 0x00.toByte(), 0x00.toByte()))

        val handshakeStart = pkt.size
        // Handshake Header: ClientHello (0x01), Handshake Length placeholder (3 bytes)
        pkt.addAll(listOf(0x01.toByte(), 0x00.toByte(), 0x00.toByte(), 0x00.toByte()))

        // Version: TLS 1.2 (0x03, 0x03)
        pkt.addAll(listOf(0x03.toByte(), 0x03.toByte()))

        // Random: 32 bytes
        for (i in 0 until 32) {
            pkt.add(0x42.toByte())
        }

        // Session ID: len 0
        pkt.add(0x00.toByte())

        // Cipher Suites: 2 bytes len + 2 suites (4 bytes)
        pkt.addAll(listOf(0x00.toByte(), 0x04.toByte(), 0x13.toByte(), 0x01.toByte(), 0x13.toByte(), 0x02.toByte()))

        // Compression: len 1 + null compression (0x00)
        pkt.addAll(listOf(0x01.toByte(), 0x00.toByte()))

        // Extensions
        val extLenPos = pkt.size
        pkt.addAll(listOf(0x00.toByte(), 0x00.toByte()))

        val extStart = pkt.size

        // Extension: Server Name Indication (0x0000)
        val sniExtLen = 2 + 1 + 2 + hostBytes.size
        pkt.addAll(listOf(0x00.toByte(), 0x00.toByte(), ((sniExtLen ushr 8) and 0xff).toByte(), (sniExtLen and 0xff).toByte()))

        val listLen = 1 + 2 + hostBytes.size
        pkt.addAll(listOf(((listLen ushr 8) and 0xff).toByte(), (listLen and 0xff).toByte(), 0x00.toByte(), ((hostBytes.size ushr 8) and 0xff).toByte(), (hostBytes.size and 0xff).toByte()))
        for (b in hostBytes) {
            pkt.add(b)
        }

        // Fill extensions length
        val extLen = pkt.size - extStart
        pkt[extLenPos] = ((extLen ushr 8) and 0xff).toByte()
        pkt[extLenPos + 1] = (extLen and 0xff).toByte()

        // Fill handshake length
        val hsLen = pkt.size - handshakeStart - 4
        pkt[handshakeStart + 1] = ((hsLen ushr 16) and 0xff).toByte()
        pkt[handshakeStart + 2] = ((hsLen ushr 8) and 0xff).toByte()
        pkt[handshakeStart + 3] = (hsLen and 0xff).toByte()

        // Fill record length
        val recLen = pkt.size - 5
        pkt[3] = ((recLen ushr 8) and 0xff).toByte()
        pkt[4] = (recLen and 0xff).toByte()

        return pkt.toByteArray()
    }

    @Test
    fun testLocateSniAndExtract() {
        val clientHello = buildTestClientHello("speedtest.net")
        val located = MultiStrategyFragmenter.locateSni(clientHello)
        assertNotNull(located)
        val (offset, len) = located!!
        val host = String(clientHello, offset, len, StandardCharsets.US_ASCII)
        assertEquals("speedtest.net", host)

        val extracted = MultiStrategyFragmenter.extractSni(clientHello)
        assertEquals("speedtest.net", extracted)
    }

    @Test
    fun testTenFragmentationStrategies() {
        val clientHello = buildTestClientHello("speedtest.net")
        val settings = FinalMaskSettings()

        // 1. Raw
        val raw = MultiStrategyFragmenter.fragment(clientHello, MultiFragmentStrategy.RAW, settings)
        assertEquals(1, raw.size)
        assertTrue(raw[0].contentEquals(clientHello))

        // 2. Full5
        val full5 = MultiStrategyFragmenter.fragment(clientHello, MultiFragmentStrategy.FULL5, settings)
        assertTrue(full5.size > 1)
        assertEquals(5, full5[0].size)

        // 3. Full10
        val full10 = MultiStrategyFragmenter.fragment(clientHello, MultiFragmentStrategy.FULL10, settings)
        assertEquals(10, full10[0].size)

        // 4. Full20
        val full20 = MultiStrategyFragmenter.fragment(clientHello, MultiFragmentStrategy.FULL20, settings)
        assertEquals(20, full20[0].size)

        // 5. Half
        val half = MultiStrategyFragmenter.fragment(clientHello, MultiFragmentStrategy.HALF, settings)
        assertEquals(2, half.size)

        // 6. SniBoundary
        val sniBoundary = MultiStrategyFragmenter.fragment(clientHello, MultiFragmentStrategy.SNI_BOUNDARY, settings)
        assertEquals(2, sniBoundary.size)
        val (sniOffset, _) = MultiStrategyFragmenter.locateSni(clientHello)!!
        assertEquals(sniOffset, sniBoundary[0].size)

        // 7. SniSplit
        val sniSplit = MultiStrategyFragmenter.fragment(clientHello, MultiFragmentStrategy.SNI_SPLIT, settings)
        assertEquals(2, sniSplit.size)

        // 8. TlsRecordFrag
        val tlsFrag = MultiStrategyFragmenter.fragment(clientHello, MultiFragmentStrategy.TLS_RECORD_FRAG, settings)
        assertEquals(2, tlsFrag.size)
        assertEquals(0x16.toByte(), tlsFrag[0][0])
        assertEquals(0x16.toByte(), tlsFrag[1][0])

        // 9. TlsSniRecords
        val tlsSni = MultiStrategyFragmenter.fragment(clientHello, MultiFragmentStrategy.TLS_SNI_RECORDS, settings)
        assertEquals(2, tlsSni.size)
        assertEquals(0x16.toByte(), tlsSni[0][0])
        assertEquals(0x16.toByte(), tlsSni[1][0])

        // 10. FinalMaskTlsHello
        val finalMask = MultiStrategyFragmenter.fragment(clientHello, MultiFragmentStrategy.FINALMASK_TLS_HELLO, settings)
        assertTrue(finalMask.isNotEmpty())
    }

    @Test
    fun testFinalMaskRewrite() {
        val clientHello = buildTestClientHello("ignitelimit.com")
        val settings = FinalMaskSettings(packet = "tlshello", length = 5, delayMs = 0, maxSplit = 2)

        val rewrite = MultiStrategyFragmenter.rewriteFinalMaskWrites(clientHello, settings)
        assertTrue(rewrite.firstWrite.size > 10)
        assertEquals(0x16.toByte(), rewrite.firstWrite[0])

        val recordLen = ((rewrite.firstWrite[3].toInt() and 0xff) shl 8) or (rewrite.firstWrite[4].toInt() and 0xff)
        assertEquals(5, recordLen)

        val contiguous = MultiStrategyFragmenter.rewriteFinalMaskTlsHello(clientHello, settings)
        assertTrue(contiguous.contentEquals(rewrite.firstWrite))
    }

    @Test
    fun testCarrierRouteSelector() {
        val edge1 = CarrierEdge("104.18.1.1", 443, "primary", 2)
        val edge2 = CarrierEdge("104.18.1.2", 443, "irancell", 100)
        val edge3 = CarrierEdge("172.66.0.1", 443, "fallback", 2)

        val edges = listOf(edge1, edge2, edge3)
        var simulatedTime = 1000L
        val selector = CarrierRouteSelector(cooldownMs = 1000L, clockMs = { simulatedTime })

        val ordered = selector.orderedEdges(edges)
        assertEquals(edges, ordered)

        selector.recordFailure(edge1)
        assertTrue(selector.isInCooldown(edge1))

        val orderedAfterFail = selector.orderedEdges(edges)
        assertEquals(edge2, orderedAfterFail[0])
        assertEquals(edge3, orderedAfterFail[1])
        assertEquals(edge1, orderedAfterFail[2])

        selector.recordSuccess(edge1)
        assertTrue(!selector.isInCooldown(edge1))
        val orderedAfterSuccess = selector.orderedEdges(edges)
        assertEquals(edge1, orderedAfterSuccess[0])
    }
}
