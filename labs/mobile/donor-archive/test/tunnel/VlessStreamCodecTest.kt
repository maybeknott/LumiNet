package com.luminet.android.tunnel

import org.junit.Assert.*
import org.junit.Test
import java.net.InetAddress
import java.net.Inet4Address

class VlessStreamCodecTest {

    @Test
    fun testVlessRequestHeaderDomainRoundTrip() {
        val uuid = ByteArray(16) { 0x12.toByte() }
        val header = VlessRequestHeader(
            version = 0,
            uuid = uuid,
            command = VlessCommand.TCP,
            port = 443,
            address = VlessAddress.Domain("example.com"),
            addons = ByteArray(0)
        )

        val bytes = header.serialize()
        val (parsed, consumed) = VlessRequestHeader.deserialize(bytes)

        assertEquals(bytes.size, consumed)
        assertEquals(header.version, parsed.version)
        assertArrayEquals(header.uuid, parsed.uuid)
        assertEquals(header.command, parsed.command)
        assertEquals(header.port, parsed.port)
        assertTrue(parsed.address is VlessAddress.Domain)
        assertEquals("example.com", (parsed.address as VlessAddress.Domain).domain)
    }

    @Test
    fun testVlessRequestHeaderIPv4RoundTrip() {
        val uuid = ByteArray(16) { 0xAB.toByte() }
        val ipv4 = InetAddress.getByAddress(byteArrayOf(1, 1, 1, 1)) as Inet4Address
        val header = VlessRequestHeader(
            version = 0,
            uuid = uuid,
            command = VlessCommand.UDP,
            port = 53,
            address = VlessAddress.IPv4(ipv4),
            addons = byteArrayOf(0x05)
        )

        val bytes = header.serialize()
        val (parsed, consumed) = VlessRequestHeader.deserialize(bytes)

        assertEquals(bytes.size, consumed)
        assertEquals(header.version, parsed.version)
        assertArrayEquals(header.uuid, parsed.uuid)
        assertEquals(header.command, parsed.command)
        assertEquals(header.port, parsed.port)
        assertTrue(parsed.address is VlessAddress.IPv4)
        assertEquals(ipv4, (parsed.address as VlessAddress.IPv4).address)
        assertArrayEquals(byteArrayOf(0x05), parsed.addons)
    }

    @Test
    fun testVlessResponseHeaderRoundTrip() {
        val resp = VlessResponseHeader(version = 0, addons = byteArrayOf(1, 2, 3))
        val bytes = resp.serialize()
        val (parsed, consumed) = VlessResponseHeader.deserialize(bytes)

        assertEquals(5, consumed)
        assertEquals(0.toByte(), parsed.version)
        assertArrayEquals(byteArrayOf(1, 2, 3), parsed.addons)
    }
}
