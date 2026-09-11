package com.luminet.android.tunnel

import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertTrue
import org.junit.Test
import java.nio.charset.StandardCharsets

class MixedProtocolProxyTest {

    @Test
    fun testDetectProtocol() {
        assertEquals(ProxyProtocolKind.SOCKS5, MixedProtocolProxy.detectProtocol(0x05))
        assertEquals(ProxyProtocolKind.SOCKS4, MixedProtocolProxy.detectProtocol(0x04))
        assertEquals(ProxyProtocolKind.HTTP, MixedProtocolProxy.detectProtocol('C'.code.toByte()))
        assertEquals(ProxyProtocolKind.HTTP, MixedProtocolProxy.detectProtocol('G'.code.toByte()))
    }

    @Test
    fun testSocks4ParsingAndReply() {
        val reqBytes = byteArrayOf(
            0x04, 0x01, 0x01, 0xbb.toByte(), // CMD=1, PORT=443
            192.toByte(), 168.toByte(), 1, 100, // IP=192.168.1.100
            'a'.code.toByte(), 'd'.code.toByte(), 'm'.code.toByte(), 'i'.code.toByte(), 'n'.code.toByte(), 0x00
        )
        val (req, len) = MixedProtocolProxy.parseSocks4Request(reqBytes)
        assertEquals(reqBytes.size, len)
        assertEquals(MixedProtocolConstants.SOCKS4_CMD_CONNECT, req.command)
        assertEquals(443, req.port)
        assertEquals("admin", req.userId)
        assertFalse(req.isSocks4a())
        assertEquals("192.168.1.100", req.targetHost())

        val reply = MixedProtocolProxy.buildSocks4Reply(MixedProtocolConstants.SOCKS4_STATUS_GRANTED, 443)
        assertEquals(8, reply.size)
        assertEquals(0x00.toByte(), reply[0])
        assertEquals(MixedProtocolConstants.SOCKS4_STATUS_GRANTED, reply[1])
    }

    @Test
    fun testSocks4aDomainParsing() {
        val reqBytes = byteArrayOf(
            0x04, 0x01, 0x00, 0x50, // CMD=1, PORT=80
            0, 0, 0, 1, // IP 0.0.0.1
            0x00, // empty user id
            'e'.code.toByte(), 'x'.code.toByte(), 'a'.code.toByte(), 'm'.code.toByte(), 'p'.code.toByte(),
            'l'.code.toByte(), 'e'.code.toByte(), '.'.code.toByte(), 'o'.code.toByte(), 'r'.code.toByte(),
            'g'.code.toByte(), 0x00
        )
        val (req, len) = MixedProtocolProxy.parseSocks4Request(reqBytes)
        assertEquals(reqBytes.size, len)
        assertTrue(req.isSocks4a())
        assertEquals("example.org", req.targetHost())
        assertEquals(80, req.port)
    }

    @Test
    fun testSocks5GreetingAndRequest() {
        val greetBytes = byteArrayOf(0x05, 0x02, 0x00, 0x02)
        val (greeting, len) = MixedProtocolProxy.parseSocks5Greeting(greetBytes)
        assertEquals(4, len)
        assertEquals(2, greeting.methods.size)
        assertEquals(0x00.toByte(), greeting.methods[0])

        val reply = MixedProtocolProxy.buildSocks5GreetingReply(MixedProtocolConstants.SOCKS5_AUTH_NONE)
        assertEquals(2, reply.size)
        assertEquals(0x05.toByte(), reply[0])
        assertEquals(0x00.toByte(), reply[1])

        // Command request domain
        val domainBytes = "example.com".toByteArray(StandardCharsets.UTF_8)
        val reqBytes = byteArrayOf(
            0x05, 0x01, 0x00, 0x03,
            domainBytes.size.toByte()
        ) + domainBytes + byteArrayOf(0x20, 0xfb.toByte()) // 8443

        val (req, reqLen) = MixedProtocolProxy.parseSocks5Request(reqBytes)
        assertEquals(reqBytes.size, reqLen)
        assertEquals(MixedProtocolConstants.SOCKS5_CMD_CONNECT, req.command)
        assertEquals("example.com", req.targetHost)
        assertEquals(8443, req.targetPort)

        val cmdReply = MixedProtocolProxy.buildSocks5Reply(MixedProtocolConstants.SOCKS5_REP_SUCCESS, 8443)
        assertEquals(10, cmdReply.size)
        assertEquals(0x05.toByte(), cmdReply[0])
        assertEquals(0x00.toByte(), cmdReply[1])
    }

    @Test
    fun testHttpProxyRequest() {
        val rawConnect = "CONNECT cloudflare.com:443 HTTP/1.1\r\nHost: cloudflare.com:443\r\n\r\n"
        val req = MixedProtocolProxy.parseHttpProxyRequest(rawConnect)
        assertTrue(req.isConnect)
        assertEquals("cloudflare.com", req.host)
        assertEquals(443, req.port)

        val ok = MixedProtocolProxy.buildHttpConnectOkResponse()
        assertTrue(String(ok, StandardCharsets.US_ASCII).startsWith("HTTP/1.1 200 Connection Established"))

        val rawGet = "GET http://api.github.com/v1/status HTTP/1.1\r\nHost: api.github.com\r\n\r\n"
        val reqGet = MixedProtocolProxy.parseHttpProxyRequest(rawGet)
        assertFalse(reqGet.isConnect)
        assertEquals("api.github.com", reqGet.host)
        assertEquals(80, reqGet.port)
        assertEquals("/v1/status", reqGet.path)
    }
}
