package com.luminet.android.tunnel

import org.junit.Assert.*
import org.junit.Test

class DnsAutoTuneManagerTest {

    @Test
    fun testPresetsCountAndLookup() {
        assertEquals(10, DnsAutoTunePresets.all.size)

        val preset = DnsAutoTunePresets.getById("iran-average")
        assertNotNull(preset)
        assertEquals("Iran Default", preset?.label)
        assertEquals(40, preset?.minUploadMtu)
        assertEquals(140, preset?.maxUploadMtu)
        assertEquals(300, preset?.minDownloadMtu)
        assertEquals(3000, preset?.maxDownloadMtu)
        assertEquals(AutoTunePresetStability.STABLE, preset?.stability)

        val agg = DnsAutoTunePresets.getById("iran-wide-range-aggressive")
        assertNotNull(agg)
        assertEquals(AutoTunePresetStability.AGGRESSIVE, agg?.stability)
    }

    @Test
    fun testRoundRobinChunking() {
        val list = listOf("1.1.1.1", "8.8.8.8", "9.9.9.9", "8.8.4.4")
        val chunks = chunkResolversRoundRobin(list, 2)
        assertEquals(2, chunks.size)
        assertEquals(listOf("1.1.1.1", "9.9.9.9"), chunks[0])
        assertEquals(listOf("8.8.8.8", "8.8.4.4"), chunks[1])
    }

    @Test
    fun testProfileLinkRoundTrip() {
        val record = DnsProfileRecord(
            name = "Android Resolver",
            domain = "dns.mobile.net",
            encryptionKey = "key789123",
            encryptionMethod = 2,
            engine = "stormdns"
        )

        val link = DnsProfileLinkManager.encode(record)
        assertTrue(link.startsWith("stormdns://"))

        val decoded = DnsProfileLinkManager.decode(link)
        assertEquals(record.name, decoded.name)
        assertEquals(record.domain, decoded.domain)
        assertEquals(record.encryptionKey, decoded.encryptionKey)
        assertEquals(record.encryptionMethod, decoded.encryptionMethod)
        assertEquals(record.engine, decoded.engine)
    }
}
