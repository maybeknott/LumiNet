package com.luminet.android.tunnel

import java.net.Inet4Address
import java.net.Inet6Address
import java.net.InetAddress
import java.net.InetSocketAddress
import java.nio.ByteBuffer
import java.nio.ByteOrder
import java.util.concurrent.atomic.AtomicBoolean
import java.util.concurrent.atomic.AtomicLong

/**
 * Tun2Socks Virtual Router & BadVPN UDP Gateway (udpgw) Interface Bridge.
 * Conforms to strict architectural isolation rules: zero vendor prefixes.
 */
class Tun2SocksBridge {
    companion object {
        const val UDPGW_CLIENT_FLAG_IPV6: Byte = 0x01
        const val UDPGW_CLIENT_FLAG_DNS: Byte = 0x02
        const val DEFAULT_MTU = 1500
        const val MAX_FRAME_SIZE = 65535
    }

    /**
     * VPN Interface configuration passed to userspace packet router.
     */
    data class Tun2SocksConfig(
        val vpnInterfaceFd: Int,
        val vpnInterfaceMTU: Int = DEFAULT_MTU,
        val vpnIpv4Address: String = "10.0.0.2",
        val vpnIpv4NetMask: String = "255.255.255.0",
        val vpnIpv6Address: String? = null,
        val socksServerAddress: String = "127.0.0.1:1080",
        val udpgwServerAddress: String = "127.0.0.1:7300",
        val udpgwTransparentDNS: Boolean = true
    )

    /**
     * BadVPN UDP Gateway wire frame.
     */
    data class UdpGwFrame(
        val flags: Byte,
        val remoteAddress: InetSocketAddress,
        val payload: ByteArray
    ) {
        fun encode(): ByteArray {
            val isV6 = remoteAddress.address is Inet6Address
            val ipBytes = remoteAddress.address.address
            val out = ByteBuffer.allocate(1 + ipBytes.size + 2 + payload.size).order(ByteOrder.BIG_ENDIAN)

            var f = flags.toInt()
            if (isV6) {
                f = f or UDPGW_CLIENT_FLAG_IPV6.toInt()
            }
            out.put(f.toByte())
            out.put(ipBytes)
            out.putShort(remoteAddress.port.toShort())
            out.put(payload)
            return out.array()
        }

        companion object {
            fun decode(buf: ByteArray): UdpGwFrame {
                if (buf.isEmpty()) {
                    throw IllegalArgumentException("Empty UDPGW frame buffer")
                }
                val flags = buf[0]
                val isV6 = (flags.toInt() and UDPGW_CLIENT_FLAG_IPV6.toInt()) != 0
                val ipLen = if (isV6) 16 else 4

                if (buf.size < 1 + ipLen + 2) {
                    throw IllegalArgumentException("UDPGW frame too short")
                }

                val ipBytes = buf.copyOfRange(1, 1 + ipLen)
                val inetAddr = InetAddress.getByAddress(ipBytes)

                val portOffset = 1 + ipLen
                val port = ByteBuffer.wrap(buf, portOffset, 2).order(ByteOrder.BIG_ENDIAN).short.toInt() and 0xFFFF
                val payload = buf.copyOfRange(portOffset + 2, buf.size)

                return UdpGwFrame(
                    flags = flags,
                    remoteAddress = InetSocketAddress(inetAddr, port),
                    payload = payload
                )
            }
        }

        override fun equals(other: Any?): Boolean {
            if (this === other) return true
            if (javaClass != other?.javaClass) return false
            other as UdpGwFrame
            if (flags != other.flags) return false
            if (remoteAddress != other.remoteAddress) return false
            if (!payload.contentEquals(other.payload)) return false
            return true
        }

        override fun hashCode(): Int {
            var result = flags.toInt()
            result = 31 * result + remoteAddress.hashCode()
            result = 31 * result + payload.contentHashCode()
            return result
        }
    }

    private val running = AtomicBoolean(false)
    private var activeConfig: Tun2SocksConfig? = null
    private val packetsForwarded = AtomicLong(0)
    private val bytesTx = AtomicLong(0)
    private val bytesRx = AtomicLong(0)

    @Synchronized
    fun start(config: Tun2SocksConfig): Boolean {
        if (running.get()) {
            return false
        }
        activeConfig = config
        running.set(true)
        packetsForwarded.set(0)
        bytesTx.set(0)
        bytesRx.set(0)
        return true
    }

    @Synchronized
    fun stop(): Boolean {
        if (!running.get()) {
            return false
        }
        running.set(false)
        activeConfig = null
        return true
    }

    fun isRunning(): Boolean = running.get()

    fun recordTraffic(tx: Long, rx: Long) {
        packetsForwarded.incrementAndGet()
        bytesTx.addAndGet(tx)
        bytesRx.addAndGet(rx)
    }

    fun getStats(): Map<String, Long> {
        return mapOf(
            "packetsForwarded" to packetsForwarded.get(),
            "bytesTx" to bytesTx.get(),
            "bytesRx" to bytesRx.get()
        )
    }
}
