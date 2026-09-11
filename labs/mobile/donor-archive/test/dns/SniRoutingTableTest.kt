package com.luminet.android.dns

import org.junit.Assert.*
import org.junit.Test

class SniRoutingTableTest {

    @Test
    fun testExactAndWildcardResolution() {
        val table = SniRoutingTable()
        table.addExactRoute("youtube.com", "142.250.180.14")
        table.addWildcardRoute("*.googlevideo.com", "142.250.180.14")
        table.addSubstringRoute("google", "142.250.180.46")

        // Exact
        assertEquals("142.250.180.14", table.resolveRoute("youtube.com"))
        assertEquals("142.250.180.14", table.resolveRoute("YouTube.COM."))

        // Wildcard
        assertEquals("142.250.180.14", table.resolveRoute("rr1.googlevideo.com"))
        assertEquals("142.250.180.14", table.resolveRoute("googlevideo.com"))

        // Substring
        assertEquals("142.250.180.46", table.resolveRoute("auth.google.internal"))

        // Miss
        assertNull(table.resolveRoute("example.org"))
        assertEquals(3, table.totalRoutes())
    }

    @Test
    fun testPrecedenceOrder() {
        val table = SniRoutingTable()
        table.addSubstringRoute("corp", "3.3.3.3")
        table.addWildcardRoute("*.corp.local", "2.2.2.2")
        table.addExactRoute("gateway.corp.local", "1.1.1.1")

        // Exact beats wildcard
        assertEquals("1.1.1.1", table.resolveRoute("gateway.corp.local"))
        // Wildcard beats substring
        assertEquals("2.2.2.2", table.resolveRoute("api.corp.local"))
        // Substring catches rest
        assertEquals("3.3.3.3", table.resolveRoute("corp-portal.net"))
    }
}
