package com.luminet.android.tunnel

import java.io.ByteArrayInputStream
import java.io.ByteArrayOutputStream
import java.io.DataInputStream
import java.io.DataOutputStream
import java.net.Inet4Address
import java.net.Inet6Address
import java.net.InetAddress
import java.nio.ByteBuffer
import java.nio.ByteOrder
import java.nio.charset.StandardCharsets

/**
 * Raw Packet Evasion Codec & Wire Protocol.
 *
 * Ported and unified from `paqet-master`.
 * Provides raw TCP packet crafting utilities, IPv4/IPv6 pseudo-header checksum calculation,
 * TCP flag bitfield manipulation, KCP transport mode presets, and tunnel multiplexing frames.
 */
object RawPacketConstants {
    const val MAGIC: Byte = 0x50 // 'P'
    const val VERSION: Byte = 0x01

    const val MSG_PING: Byte = 0x01
    const val MSG_PONG: Byte = 0x02
    const val MSG_TCPF: Byte = 0x03
    const val MSG_TCP: Byte = 0x04
    const val MSG_UDP: Byte = 0x05

    const val HEADER_LEN: Int = 5
    const val MAX_HOST_LEN: Int = 253
    const val MAX_TCPF_COUNT: Int = 64
    const val MAX_BODY_LEN: Int = 4096

    const val FLAG_FIN: Int = 1 shl 0
    const val FLAG_SYN: Int = 1 shl 1
    const val FLAG_RST: Int = 1 shl 2
    const val FLAG_PSH: Int = 1 shl 3
    const val FLAG_ACK: Int = 1 shl 4
    const val FLAG_URG: Int = 1 shl 5
    const val FLAG_ECE: Int = 1 shl 6
    const val FLAG_CWR: Int = 1 shl 7
    const val FLAG_NS: Int = 1 shl 8
}

/**
 * Structured TCP control flags for crafted evasion bursts.
 */
data class RawTcpFlags(
    val fin: Boolean = false,
    val syn: Boolean = false,
    val rst: Boolean = false,
    val psh: Boolean = false,
    val ack: Boolean = false,
    val urg: Boolean = false,
    val ece: Boolean = false,
    val cwr: Boolean = false,
    val ns: Boolean = false
) {
    fun encode(): Int {
        var v = 0
        if (fin) v = v or RawPacketConstants.FLAG_FIN
        if (syn) v = v or RawPacketConstants.FLAG_SYN
        if (rst) v = v or RawPacketConstants.FLAG_RST
        if (psh) v = v or RawPacketConstants.FLAG_PSH
        if (ack) v = v or RawPacketConstants.FLAG_ACK
        if (urg) v = v or RawPacketConstants.FLAG_URG
        if (ece) v = v or RawPacketConstants.FLAG_ECE
        if (cwr) v = v or RawPacketConstants.FLAG_CWR
        if (ns) v = v or RawPacketConstants.FLAG_NS
        return v
    }

    fun toFlagStr(): String {
        val sb = StringBuilder()
        if (fin) sb.append('F')
        if (syn) sb.append('S')
        if (rst) sb.append('R')
        if (psh) sb.append('P')
        if (ack) sb.append('A')
        if (urg) sb.append('U')
        if (ece) sb.append('E')
        if (cwr) sb.append('C')
        if (ns) sb.append('N')
        return sb.toString()
    }

    companion object {
        fun decode(v: Int): RawTcpFlags {
            return RawTcpFlags(
                fin = (v and RawPacketConstants.FLAG_FIN) != 0,
                syn = (v and RawPacketConstants.FLAG_SYN) != 0,
                rst = (v and RawPacketConstants.FLAG_RST) != 0,
                psh = (v and RawPacketConstants.FLAG_PSH) != 0,
                ack = (v and RawPacketConstants.FLAG_ACK) != 0,
                urg = (v and RawPacketConstants.FLAG_URG) != 0,
                ece = (v and RawPacketConstants.FLAG_ECE) != 0,
                cwr = (v and RawPacketConstants.FLAG_CWR) != 0,
                ns = (v and RawPacketConstants.FLAG_NS) != 0
            )
        }

        fun parseStr(s: String): RawTcpFlags {
            var fin = false
            var syn = false
            var rst = false
            var psh = false
            var ack = false
            var urg = false
            var ece = false
            var cwr = false
            var ns = false

            for (ch in s) {
                when (ch) {
                    'F', 'f' -> fin = true
                    'S', 's' -> syn = true
                    'R', 'r' -> rst = true
                    'P', 'p' -> psh = true
                    'A', 'a' -> ack = true
                    'U', 'u' -> urg = true
                    'E', 'e' -> ece = true
                    'C', 'c' -> cwr = true
                    'N', 'n' -> ns = true
                    else -> throw IllegalArgumentException("Invalid TCP flag character: '$ch'")
                }
            }
            return RawTcpFlags(fin, syn, rst, psh, ack, urg, ece, cwr, ns)
        }
    }
}

data class TargetEndpoint(
    val host: String,
    val port: Int
)

sealed class RawPacketMessage {
    object Ping : RawPacketMessage()
    object Pong : RawPacketMessage()
    data class Tcpf(val flags: List<RawTcpFlags>) : RawPacketMessage()
    data class Tcp(val target: TargetEndpoint) : RawPacketMessage()
    data class Udp(val target: TargetEndpoint) : RawPacketMessage()
}

object RawPacketCodec {
    fun encode(msg: RawPacketMessage): ByteArray {
        val bodyOut = ByteArrayOutputStream()
        val bodyData = DataOutputStream(bodyOut)
        val msgType: Byte

        when (msg) {
            is RawPacketMessage.Ping -> {
                msgType = RawPacketConstants.MSG_PING
            }
            is RawPacketMessage.Pong -> {
                msgType = RawPacketConstants.MSG_PONG
            }
            is RawPacketMessage.Tcp -> {
                msgType = RawPacketConstants.MSG_TCP
                val hostBytes = msg.target.host.toByteArray(StandardCharsets.UTF_8)
                require(hostBytes.size <= RawPacketConstants.MAX_HOST_LEN) { "Host length exceeds max limit" }
                require(msg.target.port in 0..0xFFFF) { "Port out of range" }
                bodyData.writeByte(hostBytes.size)
                bodyData.write(hostBytes)
                bodyData.writeShort(msg.target.port)
            }
            is RawPacketMessage.Udp -> {
                msgType = RawPacketConstants.MSG_UDP
                val hostBytes = msg.target.host.toByteArray(StandardCharsets.UTF_8)
                require(hostBytes.size <= RawPacketConstants.MAX_HOST_LEN) { "Host length exceeds max limit" }
                require(msg.target.port in 0..0xFFFF) { "Port out of range" }
                bodyData.writeByte(hostBytes.size)
                bodyData.write(hostBytes)
                bodyData.writeShort(msg.target.port)
            }
            is RawPacketMessage.Tcpf -> {
                msgType = RawPacketConstants.MSG_TCPF
                require(msg.flags.size <= RawPacketConstants.MAX_TCPF_COUNT) { "TCPF count exceeds limit" }
                bodyData.writeByte(msg.flags.size)
                for (f in msg.flags) {
                    bodyData.writeShort(f.encode())
                }
            }
        }
        bodyData.flush()
        val body = bodyOut.toByteArray()
        require(body.size <= RawPacketConstants.MAX_BODY_LEN) { "Body exceeds max length" }

        val out = ByteArrayOutputStream()
        val outData = DataOutputStream(out)
        outData.writeByte(RawPacketConstants.MAGIC.toInt())
        outData.writeByte(RawPacketConstants.VERSION.toInt())
        outData.writeByte(msgType.toInt())
        outData.writeShort(body.size)
        outData.write(body)
        outData.flush()
        return out.toByteArray()
    }

    fun decode(bytes: ByteArray): Pair<RawPacketMessage, Int> {
        if (bytes.size < RawPacketConstants.HEADER_LEN) {
            throw IllegalArgumentException("Buffer too short for header")
        }
        if (bytes[0] != RawPacketConstants.MAGIC) {
            throw IllegalArgumentException("Bad magic byte: ${bytes[0]}")
        }
        if (bytes[1] != RawPacketConstants.VERSION) {
            throw IllegalArgumentException("Unsupported version: ${bytes[1]}")
        }

        val msgType = bytes[2]
        val bodyLen = ByteBuffer.wrap(bytes, 3, 2).order(ByteOrder.BIG_ENDIAN).short.toInt() and 0xFFFF
        val totalLen = RawPacketConstants.HEADER_LEN + bodyLen
        if (bytes.size < totalLen) {
            throw IllegalArgumentException("Buffer too short for complete frame")
        }

        val bodyStream = ByteArrayInputStream(bytes, RawPacketConstants.HEADER_LEN, bodyLen)
        val bodyData = DataInputStream(bodyStream)

        val msg: RawPacketMessage = when (msgType) {
            RawPacketConstants.MSG_PING -> RawPacketMessage.Ping
            RawPacketConstants.MSG_PONG -> RawPacketMessage.Pong
            RawPacketConstants.MSG_TCP -> {
                val hostLen = bodyData.readByte().toInt() and 0xFF
                val hostBytes = ByteArray(hostLen)
                bodyData.readFully(hostBytes)
                val host = String(hostBytes, StandardCharsets.UTF_8)
                val port = bodyData.readUnsignedShort()
                RawPacketMessage.Tcp(TargetEndpoint(host, port))
            }
            RawPacketConstants.MSG_UDP -> {
                val hostLen = bodyData.readByte().toInt() and 0xFF
                val hostBytes = ByteArray(hostLen)
                bodyData.readFully(hostBytes)
                val host = String(hostBytes, StandardCharsets.UTF_8)
                val port = bodyData.readUnsignedShort()
                RawPacketMessage.Udp(TargetEndpoint(host, port))
            }
            RawPacketConstants.MSG_TCPF -> {
                val count = bodyData.readByte().toInt() and 0xFF
                val list = mutableListOf<RawTcpFlags>()
                for (i in 0 until count) {
                    val flagVal = bodyData.readUnsignedShort()
                    list.add(RawTcpFlags.decode(flagVal))
                }
                RawPacketMessage.Tcpf(list)
            }
            else -> throw IllegalArgumentException("Unknown message type: $msgType")
        }

        return Pair(msg, totalLen)
    }
}

/**
 * Standard RFC 1071 16-bit One's Complement Internet Checksum.
 */
object InternetChecksum {
    fun compute(data: ByteArray): Int {
        var sum = 0L
        var i = 0
        while (i + 1 < data.size) {
            val word = ((data[i].toInt() and 0xFF) shl 8) or (data[i + 1].toInt() and 0xFF)
            sum += word
            i += 2
        }
        if (i < data.size) {
            sum += (data[i].toInt() and 0xFF) shl 8
        }
        while ((sum shr 16) > 0) {
            sum = (sum and 0xFFFF) + (sum shr 16)
        }
        return (sum.inv() and 0xFFFF).toInt()
    }

    fun tcpIpv4Checksum(src: Inet4Address, dst: Inet4Address, tcpHdrAndPayload: ByteArray): Int {
        var sum = 0L
        val srcBytes = src.address
        val dstBytes = dst.address

        sum += (((srcBytes[0].toInt() and 0xFF) shl 8) or (srcBytes[1].toInt() and 0xFF))
        sum += (((srcBytes[2].toInt() and 0xFF) shl 8) or (srcBytes[3].toInt() and 0xFF))

        sum += (((dstBytes[0].toInt() and 0xFF) shl 8) or (dstBytes[1].toInt() and 0xFF))
        sum += (((dstBytes[2].toInt() and 0xFF) shl 8) or (dstBytes[3].toInt() and 0xFF))

        sum += 6 // Protocol 6 (TCP)
        sum += tcpHdrAndPayload.size

        var i = 0
        while (i + 1 < tcpHdrAndPayload.size) {
            val word = ((tcpHdrAndPayload[i].toInt() and 0xFF) shl 8) or (tcpHdrAndPayload[i + 1].toInt() and 0xFF)
            sum += word
            i += 2
        }
        if (i < tcpHdrAndPayload.size) {
            sum += (tcpHdrAndPayload[i].toInt() and 0xFF) shl 8
        }

        while ((sum shr 16) > 0) {
            sum = (sum and 0xFFFF) + (sum shr 16)
        }
        return (sum.inv() and 0xFFFF).toInt()
    }
}

/**
 * KCP Transport Profile settings preset.
 */
data class KcpTransportProfile(
    val mode: String,
    val noDelay: Int,
    val interval: Int,
    val resend: Int,
    val noCongestion: Int,
    val wDelay: Boolean,
    val ackNoDelay: Boolean,
    val mtu: Int = 1350,
    val sndwnd: Int = 128,
    val rcvwnd: Int = 512,
    val dscp: Int = 46
) {
    companion object {
        fun fromMode(mode: String): KcpTransportProfile {
            return when (mode.trim().lowercase()) {
                "fast" -> KcpTransportProfile(
                    mode = "fast",
                    noDelay = 0,
                    interval = 30,
                    resend = 2,
                    noCongestion = 1,
                    wDelay = true,
                    ackNoDelay = false
                )
                "fast2" -> KcpTransportProfile(
                    mode = "fast2",
                    noDelay = 1,
                    interval = 20,
                    resend = 2,
                    noCongestion = 1,
                    wDelay = false,
                    ackNoDelay = true
                )
                "fast3" -> KcpTransportProfile(
                    mode = "fast3",
                    noDelay = 1,
                    interval = 10,
                    resend = 2,
                    noCongestion = 1,
                    wDelay = false,
                    ackNoDelay = true
                )
                else -> KcpTransportProfile(
                    mode = "normal",
                    noDelay = 0,
                    interval = 40,
                    resend = 2,
                    noCongestion = 1,
                    wDelay = true,
                    ackNoDelay = false
                )
            }
        }
    }
}
