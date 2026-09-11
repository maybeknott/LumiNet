package com.luminet.android.tunnel

import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertNotNull
import org.junit.Assert.assertNull
import org.junit.Assert.assertTrue
import org.junit.Test

class DnsVpnProtocolTest {

    @Test
    fun `test lower base36 encoding and decoding roundtrip`() {
        val input = "Hello, DNS Tunnel!".toByteArray(Charsets.UTF_8)
        val encoded = LowerBase36.encode(input)
        assertTrue(encoded.isNotEmpty())
        assertTrue(encoded.all { it in '0'..'9' || it in 'a'..'z' })

        val decoded = LowerBase36.decode(encoded)
        assertEquals(String(input, Charsets.UTF_8), String(decoded, Charsets.UTF_8))
    }

    @Test
    fun `test multilevel queue priority ordering and deduplication`() {
        val mlq = MultiLevelQueue<String>(16)

        assertTrue(mlq.push(5, 105L, "p5"))
        assertTrue(mlq.push(2, 102L, "p2"))
        assertTrue(mlq.push(0, 100L, "p0"))

        // Duplicate key fails
        assertFalse(mlq.push(0, 100L, "dup"))

        assertEquals(3, mlq.size())

        // Highest priority first
        val first = mlq.pop()
        assertNotNull(first)
        assertEquals("p0", first!!.first)
        assertEquals(0, first.second)

        // Remove by key
        val removed = mlq.removeByKey(105L)
        assertEquals("p5", removed)

        // Remaining
        val second = mlq.pop()
        assertNotNull(second)
        assertEquals("p2", second!!.first)
        assertEquals(2, second.second)

        assertNull(mlq.pop())
    }

    @Test
    fun `test packed control block serialization`() {
        val b1 = PackedControlBlock(1, 42, 100, 0, 1)
        val b2 = PackedControlBlock(6, 88, 200, 1, 2)

        val packed = PackedControlBlock.packBlocks(listOf(b1, b2))
        assertEquals(14, packed.size)

        val unpacked = PackedControlBlock.parseBlocks(packed)
        assertEquals(2, unpacked.size)
        assertEquals(b1, unpacked[0])
        assertEquals(b2, unpacked[1])
    }
}
