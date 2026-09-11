package com.luminet.android.tunnel

import org.junit.Assert.assertEquals
import org.junit.Assert.assertNotNull
import org.junit.Assert.assertTrue
import org.junit.Test
import java.nio.charset.StandardCharsets

class AdaptiveStrategyRacerTest {

    private fun buildTestClientHello(sniHost: String): ByteArray {
        val hostBytes = sniHost.toByteArray(StandardCharsets.US_ASCII)
        val pkt = mutableListOf<Byte>()

        pkt.addAll(listOf(0x16.toByte(), 0x03.toByte(), 0x01.toByte(), 0x00.toByte(), 0x00.toByte()))
        val handshakeStart = pkt.size
        pkt.addAll(listOf(0x01.toByte(), 0x00.toByte(), 0x00.toByte(), 0x00.toByte()))
        pkt.addAll(listOf(0x03.toByte(), 0x03.toByte()))
        for (i in 0 until 32) pkt.add(0x42.toByte())
        pkt.add(0x00.toByte())
        pkt.addAll(listOf(0x00.toByte(), 0x04.toByte(), 0x13.toByte(), 0x01.toByte(), 0x13.toByte(), 0x02.toByte()))
        pkt.addAll(listOf(0x01.toByte(), 0x00.toByte()))

        val extLenPos = pkt.size
        pkt.addAll(listOf(0x00.toByte(), 0x00.toByte()))
        val extStart = pkt.size

        val sniExtLen = 2 + 1 + 2 + hostBytes.size
        pkt.addAll(listOf(0x00.toByte(), 0x00.toByte(), ((sniExtLen ushr 8) and 0xff).toByte(), (sniExtLen and 0xff).toByte()))
        val listLen = 1 + 2 + hostBytes.size
        pkt.addAll(listOf(((listLen ushr 8) and 0xff).toByte(), (listLen and 0xff).toByte(), 0x00.toByte(), ((hostBytes.size ushr 8) and 0xff).toByte(), (hostBytes.size and 0xff).toByte()))
        for (b in hostBytes) pkt.add(b)

        val extLen = pkt.size - extStart
        pkt[extLenPos] = ((extLen ushr 8) and 0xff).toByte()
        pkt[extLenPos + 1] = (extLen and 0xff).toByte()

        val hsLen = pkt.size - handshakeStart - 4
        pkt[handshakeStart + 1] = ((hsLen ushr 16) and 0xff).toByte()
        pkt[handshakeStart + 2] = ((hsLen ushr 8) and 0xff).toByte()
        pkt[handshakeStart + 3] = (hsLen and 0xff).toByte()

        val recLen = pkt.size - 5
        pkt[3] = ((recLen ushr 8) and 0xff).toByte()
        pkt[4] = (recLen and 0xff).toByte()

        return pkt.toByteArray()
    }

    @Test
    fun testSniCharsFragmentation() {
        val clientHello = buildTestClientHello("mci.ir")
        val frags = AdaptiveStrategyRacer.fragmentExtended(clientHello, ExtendedFragmentStrategy.SNI_CHARS)
        assertEquals(7, frags.size) // prefix + 6 chars (no trailing extensions) = 7 slices

        val loc = MultiStrategyFragmenter.locateSni(clientHello)!!
        assertEquals(loc.first, frags[0].size)
        for (i in 1..6) {
            assertEquals(1, frags[i].size)
        }

        val reconstructed = frags.reduce { acc, bytes -> acc + bytes }
        assertTrue(reconstructed.contentEquals(clientHello))
    }

    @Test
    fun testMulti64Fragmentation() {
        val clientHello = buildTestClientHello("speedtest.net")
        val frags = AdaptiveStrategyRacer.fragmentExtended(clientHello, ExtendedFragmentStrategy.MULTI64, 64)
        assertTrue(frags.size > 1)
        assertEquals(64, frags[0].size)

        val reconstructed = frags.reduce { acc, bytes -> acc + bytes }
        assertTrue(reconstructed.contentEquals(clientHello))
    }

    @Test
    fun testResponseValidation() {
        assertEquals(StrategyResponseStatus.EMPTY_RESPONSE, AdaptiveStrategyRacer.validateStrategyResponse(null))

        val alert = byteArrayOf(0x15, 0x03, 0x03, 0x00, 0x02, 0x02, 0x28)
        assertEquals(StrategyResponseStatus.ALERT_REJECTED, AdaptiveStrategyRacer.validateStrategyResponse(alert))

        val truncated = byteArrayOf(0x16, 0x03, 0x03, 0x00)
        assertEquals(StrategyResponseStatus.TRUNCATED_MALFORMED, AdaptiveStrategyRacer.validateStrategyResponse(truncated))

        val valid = byteArrayOf(0x16, 0x03, 0x03, 0x00, 0x50, 0x02, 0x00, 0x00, 0x4c)
        assertEquals(StrategyResponseStatus.VALID, AdaptiveStrategyRacer.validateStrategyResponse(valid))
    }

    @Test
    fun testDisposableFakeProbe() {
        val probe = AdaptiveStrategyRacer.buildDisposableFakeProbe("speedtest.net")
        assertTrue(probe.size > 50)
        assertEquals(0x16.toByte(), probe[0])
        assertEquals(0x01.toByte(), probe[5])

        val host = MultiStrategyFragmenter.extractSni(probe)
        assertEquals("speedtest.net", host)
    }

    @Test
    fun testAdaptiveStrategyRacer() {
        val racer = AdaptiveStrategyRacer(carrierMode = CarrierMode.MCI, fakeSni = "speedtest.net")
        val plan = racer.planStrategies("104.18.8.83")
        assertTrue(plan.isNotEmpty())
        assertEquals(ExtendedFragmentStrategy.FULL20, plan[0].strategy)

        racer.recordSuccess("104.18.8.83", ExtendedFragmentStrategy.SNI_CHARS)
        assertEquals(ExtendedFragmentStrategy.SNI_CHARS, racer.preferredStrategy("104.18.8.83"))

        val updated = racer.planStrategies("104.18.8.83")
        assertEquals(ExtendedFragmentStrategy.SNI_CHARS, updated[0].strategy)
    }
}
