package com.luminet.android.tunnel

import org.junit.Assert.*
import org.junit.Test

class RangeParallelDownloaderTest {

    @Test
    fun testComputeChunks() {
        val chunks = RangeChunkCalculator.computeChunks(700000L, 262144L)
        assertEquals(3, chunks.size)

        assertEquals(0L, chunks[0].start)
        assertEquals(262143L, chunks[0].end)
        assertEquals("bytes=0-262143", chunks[0].toRangeHeader())

        assertEquals(262144L, chunks[1].start)
        assertEquals(524287L, chunks[1].end)

        assertEquals(524288L, chunks[2].start)
        assertEquals(699999L, chunks[2].end)
    }

    @Test
    fun testParseContentRange() {
        val parsed = RangeChunkCalculator.parseContentRange("bytes 0-262143/1048576")
        assertNotNull(parsed)
        assertEquals(0L, parsed!!.first)
        assertEquals(262143L, parsed.second)
        assertEquals(1048576L, parsed.third)

        assertNull(RangeChunkCalculator.parseContentRange("invalid"))
        assertNull(RangeChunkCalculator.parseContentRange("bytes 200-100/500"))
        assertNull(RangeChunkCalculator.parseContentRange("bytes 0-500/500"))
    }

    @Test
    fun testRangeParallelStitcher() {
        val stitcher = RangeParallelStitcher(30L)
        val chunk0 = byteArrayOf(1, 2, 3, 4, 5, 6, 7, 8, 9, 10)
        val chunk1 = byteArrayOf(11, 12, 13, 14, 15, 16, 17, 18, 19, 20)
        val chunk2 = byteArrayOf(21, 22, 23, 24, 25, 26, 27, 28, 29, 30)

        // Ingest out-of-order chunk 1
        stitcher.ingest(10L, chunk1)
        assertEquals(0, stitcher.drainContiguous().size)
        assertFalse(stitcher.isComplete())

        // Ingest chunk 2
        stitcher.ingest(20L, chunk2)
        assertEquals(0, stitcher.drainContiguous().size)

        // Ingest chunk 0
        stitcher.ingest(0L, chunk0)

        val drained = stitcher.drainContiguous()
        assertEquals(30, drained.size)
        for (i in 0 until 30) {
            assertEquals((i + 1).toByte(), drained[i])
        }
        assertTrue(stitcher.isComplete())
    }
}
