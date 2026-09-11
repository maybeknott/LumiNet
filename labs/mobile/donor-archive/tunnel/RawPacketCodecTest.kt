package com.luminet.android.tunnel

import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertNotEquals
import org.junit.Assert.assertTrue
import org.junit.Assert.fail
import org.junit.Test
import java.net.Inet4Address
import java.net.InetAddress

class RawPacketCodecTest {

    @Test
    fun testFlagParsingAndBitfield() {
        val flags = RawTcpFlags.parseStr("PA")
        assertTrue(flags.psh)
        assertTrue(flags.ack)
        assertFalse(flags.syn)
        assertEquals("PA", flags.toFlagStr())

        val encoded = flags.encode()
        val decoded = RawTcpFlags.decode(encoded)
        assertEquals(flags, decoded)

        val full = RawTcpFlags.parseStr("FSRPAUECN")
        assertEquals("FSRPAUECN", full.toFlagStr())

        try {
            RawTcpFlags.parseStr("PZ")
            fail("Expected exception for invalid flag")
        } catch (e: IllegalArgumentException) {
            // Success
        }
    }

    @Test
    fun testPingPongCodec() {
        val pingBytes = RawPacketCodec.encode(RawPacketMessage.Ping)
        assertEquals(RawPacketConstants.HEADER_LEN, pingBytes.size)
        assertEquals(RawPacketConstants.MAGIC, pingBytes[0])
        assertEquals(RawPacketConstants.VERSION, pingBytes[1])
        assertEquals(RawPacketConstants.MSG_PING, pingBytes[2])

        val (decodedPing, consumedPing) = RawPacketCodec.decode(pingBytes)
        assertEquals(RawPacketConstants.HEADER_LEN, consumedPing)
        assertTrue(decodedPing is RawPacketMessage.Ping)

        val pongBytes = RawPacketCodec.encode(RawPacketMessage.Pong)
        val (decodedPong, consumedPong) = RawPacketCodec.decode(pongBytes)
        assertEquals(RawPacketConstants.HEADER_LEN, consumedPong)
        assertTrue(decodedPong is RawPacketMessage.Pong)
    }

    @Test
    fun testTcpAndUdpTargetCodec() {
        val target = TargetEndpoint("api.edge.cloudflare.com", 443)
        val tcpMsg = RawPacketMessage.Tcp(target)
        val encoded = RawPacketCodec.encode(tcpMsg)

        val (decoded, len) = RawPacketCodec.decode(encoded)
        assertEquals(encoded.size, len)
        assertTrue(decoded is RawPacketMessage.Tcp)
        assertEquals("api.edge.cloudflare.com", (decoded as RawPacketMessage.Tcp).target.host)
        assertEquals(443, decoded.target.port)

        val udpMsg = RawPacketMessage.Udp(TargetEndpoint("1.1.1.1", 53))
        val encodedUdp = RawPacketCodec.encode(udpMsg)
        val (decodedUdp, lenUdp) = RawPacketCodec.decode(encodedUdp)
        assertEquals(encodedUdp.size, lenUdp)
        assertTrue(decodedUdp is RawPacketMessage.Udp)
        assertEquals("1.1.1.1", (decodedUdp as RawPacketMessage.Udp).target.host)
        assertEquals(53, (decodedUdp as RawPacketMessage.Udp).target.port)
    }

    @Test
    fun testTcpfFlagsCodec() {
        val list = listOf(
            RawTcpFlags.parseStr("S"),
            RawTcpFlags.parseStr("SA"),
            RawTcpFlags.parseStr("PA")
        )
        val msg = RawPacketMessage.Tcpf(list)
        val encoded = RawPacketCodec.encode(msg)

        val (decoded, len) = RawPacketCodec.decode(encoded)
        assertEquals(encoded.size, len)
        assertTrue(decoded is RawPacketMessage.Tcpf)
        val decodedList = (decoded as RawPacketMessage.Tcpf).flags
        assertEquals(3, decodedList.size)
        assertTrue(decodedList[0].syn)
        assertFalse(decodedList[0].ack)
        assertTrue(decodedList[1].syn && decodedList[1].ack)
        assertTrue(decodedList[2].psh && decodedList[2].ack)
    }

    @Test
    fun testChecksumCalculation() {
        val src = InetAddress.getByName("192.168.1.100") as Inet4Address
        val dst = InetAddress.getByName("10.0.0.1") as Inet4Address
        val dummyPayload = byteArrayOf(0x04, 0x00, 0x1f, 0x90.toByte(), 0x00, 0x00, 0x00, 0x01, 0x50, 0x02, 0xff.toByte(), 0xff.toByte())

        val csum = InternetChecksum.tcpIpv4Checksum(src, dst, dummyPayload)
        assertNotEquals(0, csum)
    }

    @Test
    fun testKcpProfiles() {
        val fast = KcpTransportProfile.fromMode("fast")
        assertEquals(30, fast.interval)
        assertEquals(46, fast.dscp)

        val fast2 = KcpTransportProfile.fromMode("fast2")
        assertEquals(1, fast2.noDelay)
        assertEquals(20, fast2.interval)
        assertTrue(fast2.ackNoDelay)
        assertFalse(fast2.wDelay)

        val fast3 = KcpTransportProfile.fromMode("fast3")
        assertEquals(10, fast3.interval)
        assertTrue(fast3.ackNoDelay)
        assertFalse(fast3.wDelay)
    }
}
