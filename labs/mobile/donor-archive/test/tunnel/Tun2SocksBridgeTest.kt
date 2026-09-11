package com.luminet.android.tunnel

import org.junit.Assert.*
import org.junit.Test
import java.net.InetAddress
import java.net.InetSocketAddress

class Tun2SocksBridgeTest {

    @Test
    fun testUdpGwFrameRoundtripIpv4() {
        val remote = InetSocketAddress(InetAddress.getByName("8.8.8.8"), 53)
        val payload = byteArrayOf(0x12, 0x34, 0x01, 0x00, 0x00, 0x01)
        val frame = Tun2SocksBridge.UdpGwFrame(
            flags = Tun2SocksBridge.UDPGW_CLIENT_FLAG_DNS,
            remoteAddress = remote,
            payload = payload
        )

        val encoded = frame.encode()
        val decoded = Tun2SocksBridge.UdpGwFrame.decode(encoded)

        assertEquals(frame, decoded)
        assertEquals(53, decoded.remoteAddress.port)
        assertEquals("8.8.8.8", decoded.remoteAddress.address.hostAddress)
    }

    @Test
    fun testUdpGwFrameRoundtripIpv6() {
        val remote = InetSocketAddress(InetAddress.getByName("2001:4860:4860::8888"), 853)
        val payload = "TLS_DNS_PAYLOAD".toByteArray(Charsets.UTF_8)
        val frame = Tun2SocksBridge.UdpGwFrame(
            flags = 0,
            remoteAddress = remote,
            payload = payload
        )

        val encoded = frame.encode()
        assertTrue((encoded[0].toInt() and Tun2SocksBridge.UDPGW_CLIENT_FLAG_IPV6.toInt()) != 0)

        val decoded = Tun2SocksBridge.UdpGwFrame.decode(encoded)
        assertEquals(frame, decoded)
        assertEquals(853, decoded.remoteAddress.port)
    }

    @Test
    fun testTun2SocksBridgeLifecycle() {
        val bridge = Tun2SocksBridge()
        assertFalse(bridge.isRunning())

        val config = Tun2SocksBridge.Tun2SocksConfig(
            vpnInterfaceFd = 42,
            vpnInterfaceMTU = 1420,
            vpnIpv4Address = "10.10.0.2",
            socksServerAddress = "127.0.0.1:10808"
        )

        val started = bridge.start(config)
        assertTrue(started)
        assertTrue(bridge.isRunning())

        // Double start returns false
        assertFalse(bridge.start(config))

        bridge.recordTraffic(500, 1500)
        val stats = bridge.getStats()
        assertEquals(1L, stats["packetsForwarded"])
        assertEquals(500L, stats["bytesTx"])
        assertEquals(1500L, stats["bytesRx"])

        val stopped = bridge.stop()
        assertTrue(stopped)
        assertFalse(bridge.isRunning())
    }
}
