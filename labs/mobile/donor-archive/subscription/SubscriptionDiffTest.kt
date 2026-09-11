package com.luminet.android.subscription

import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertTrue
import org.junit.Test

class SubscriptionDiffTest {

    private val diff = SubscriptionDiff()

    @Test
    fun `identical lists produce Unchanged`() {
        val a = listOf(item("a"), item("b"))
        val b = listOf(item("a"), item("b"))
        assertTrue(diff.diff(a, b) is Diff.Unchanged)
    }

    @Test
    fun `added items produce Added diff`() {
        val old = listOf(item("a"))
        val new = listOf(item("a"), item("b"))
        val result = diff.diff(old, new)
        assertTrue(result is Diff.Added)
        assertEquals(1, (result as Diff.Added).newItems.size)
        assertEquals("b", result.newItems.first().alias)
    }

    @Test
    fun `removed items produce Removed diff`() {
        val old = listOf(item("a"), item("b"))
        val new = listOf(item("a"))
        val result = diff.diff(old, new)
        assertTrue(result is Diff.Removed)
        assertEquals(1, (result as Diff.Removed).removedItems.size)
        assertEquals("b", result.removedItems.first().alias)
    }

    @Test
    fun `modified item produces Modified diff`() {
        val old = listOf(item("a", port = 443))
        val new = listOf(item("a", port = 8443))
        val result = diff.diff(old, new)
        assertTrue(result is Diff.Modified)
        val pair = (result as Diff.Modified).modifiedItems.first()
        assertEquals(443, pair.first.port)
        assertEquals(8443, pair.second.port)
    }

    @Test
    fun `mixed changes produce Mixed diff`() {
        val old = listOf(item("a"), item("b"))
        val new = listOf(item("a"), item("c"), item("d"))
        val result = diff.diff(old, new)
        assertTrue(result is Diff.Mixed)
        val m = result as Diff.Mixed
        assertEquals(2, m.newItems.size)   // c, d
        assertEquals(1, m.removedItems.size) // b
        assertTrue(m.modifiedItems.isEmpty())
    }

    @Test
    fun `hasChanges reflects actual change`() {
        assertFalse(diff.diff(listOf(item("a")), listOf(item("a"))).hasChanges)
        assertTrue(diff.diff(listOf(item("a")), listOf(item("b"))).hasChanges)
    }

    @Test
    fun `summary formats correctly`() {
        assertEquals("No changes", diff.diff(listOf(item("a")), listOf(item("a"))).summary())
        assertEquals("+2 added", diff.diff(listOf(item("a")), listOf(item("a"), item("b"), item("c"))).summary())
        assertEquals("-1 removed", diff.diff(listOf(item("a"), item("b")), listOf(item("a"))).summary())
        assertEquals("~1 modified", diff.diff(listOf(item("a")), listOf(item("a", port = 99))).summary())
    }

    @Test
    fun `reorder does not produce diff`() {
        // Same items, different order — position is not a semantic change.
        val old = listOf(item("a"), item("b"), item("c"))
        val new = listOf(item("c"), item("a"), item("b"))
        assertTrue(diff.diff(old, new) is Diff.Unchanged)
    }

    @Test
    fun `parse skips malformed JSON`() {
        val lines = listOf(
            """{"protocol":"vmess","add":"a.com","port":443,"id":"uuid","net":"tcp","tls":"none"}""",
            "NOT_JSON",
            """{"protocol":"vless","add":"b.com","port":443,"id":"uid","net":"ws","tls":"reality"}""",
        )
        val items = diff.parse(lines)
        assertEquals(2, items.size)
        assertEquals("a.com", items[0].host)
        assertEquals("b.com", items[1].host)
    }

    @Test
    fun `port out of range is rejected`() {
        try {
            item("x", port = 100_000)
            error("should have thrown")
        } catch (e: IllegalArgumentException) {
            assertTrue(e.message!!.contains("port"))
        }
    }

    @Test(expected = IllegalArgumentException::class)
    fun `wrong-length hash is rejected`() {
        item("x", hash = "short")
    }

    @Test
    fun `alias is set from remark field`() {
        val lines = listOf("""{"protocol":"ss","add":"c.com","port":443,"remark":"My-SS","net":"tcp","tls":"none"}""")
        val items = diff.parse(lines)
        assertEquals("My-SS", items.first().alias)
    }

    @Test
    fun `default alias is Profile N when remark is absent`() {
        val lines = listOf("""{"protocol":"trojan","add":"d.com","port":443,"net":"tcp","tls":"none"}""")
        val items = diff.parse(lines)
        assertEquals("Profile 1", items.first().alias)
    }

    private fun item(
        label: String,
        port: Int = 443,
        hash: String = label.padStart(64, '0'),
    ) = SubscriptionItem(
        alias = label,
        protocol = "vmess",
        host = "$label.example.com",
        port = port,
        identity = "11111111-2222-3333-4444-555555555555",
        transport = "tcp",
        tls = "none",
        hash = hash,
    )
}
