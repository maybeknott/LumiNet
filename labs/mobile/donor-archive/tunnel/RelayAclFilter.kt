package com.luminet.android.tunnel

import java.net.InetAddress
import java.nio.ByteBuffer

/**
 * CIDR subnet representation for fast IPv4/IPv6 prefix matching in Android.
 */
data class RelayCidr(
    val networkAddress: ByteArray,
    val prefixLength: Int,
    val isIpv6: Boolean
) {
    fun contains(address: InetAddress): Boolean {
        val targetBytes = address.address
        if (targetBytes.size != networkAddress.size) {
            return false
        }
        if (prefixLength == 0) return true

        val fullBytes = prefixLength / 8
        val remainderBits = prefixLength % 8

        for (i in 0 until fullBytes) {
            if (networkAddress[i] != targetBytes[i]) {
                return false
            }
        }

        if (remainderBits > 0) {
            val mask = (0xFF shl (8 - remainderBits)) and 0xFF
            val netByte = networkAddress[fullBytes].toInt() and mask
            val targetByte = targetBytes[fullBytes].toInt() and mask
            if (netByte != targetByte) {
                return false
            }
        }

        return true
    }

    companion object {
        fun parse(cidr: String): RelayCidr? {
            val parts = cidr.trim().split("/")
            if (parts.size != 2) return null
            val prefix = parts[1].toIntOrNull() ?: return null
            val addr = runCatching { InetAddress.getByName(parts[0]) }.getOrNull() ?: return null
            val bytes = addr.address
            val isV6 = bytes.size == 16
            val maxPrefix = if (isV6) 128 else 32
            if (prefix < 0 || prefix > maxPrefix) return null

            return RelayCidr(bytes, prefix, isV6)
        }
    }

    override fun equals(other: Any?): Boolean {
        if (this === other) return true
        if (javaClass != other?.javaClass) return false
        other as RelayCidr
        return networkAddress.contentEquals(other.networkAddress) &&
                prefixLength == other.prefixLength &&
                isIpv6 == other.isIpv6
    }

    override fun hashCode(): Int {
        var result = networkAddress.contentHashCode()
        result = 31 * result + prefixLength
        result = 31 * result + isIpv6.hashCode()
        return result
    }
}

/**
 * Access Control List firewall for relay traffic, guarding ingress with edge whitelist
 * and egress with tracker/localhost blacklist.
 */
class RelayAclFilter(
    sourceWhitelistCidrs: List<String> = DEFAULT_EDGE_CIDRS,
    destinationBlacklistCidrs: List<String> = DEFAULT_BLOCKED_CIDRS
) {
    private val sourceWhitelist = sourceWhitelistCidrs.mapNotNull { RelayCidr.parse(it) }
    private val destinationBlacklist = destinationBlacklistCidrs.mapNotNull { RelayCidr.parse(it) }

    fun isSourceAllowed(addr: InetAddress): Boolean {
        return sourceWhitelist.any { it.contains(addr) }
    }

    fun isDestinationAllowed(addr: InetAddress): Boolean {
        return !destinationBlacklist.any { it.contains(addr) }
    }

    fun evaluate(src: InetAddress, dst: InetAddress): Boolean {
        return isSourceAllowed(src) && isDestinationAllowed(dst)
    }

    companion object {
        val DEFAULT_EDGE_CIDRS = listOf(
            "103.21.244.0/22",
            "103.22.200.0/22",
            "103.31.4.0/22",
            "104.16.0.0/12",
            "108.162.192.0/18",
            "131.0.72.0/22",
            "141.101.64.0/18",
            "162.158.0.0/15",
            "172.64.0.0/13",
            "173.245.48.0/20",
            "188.114.96.0/20",
            "190.93.240.0/20",
            "197.234.240.0/22",
            "198.41.128.0/17",
            "2400:cb00::/32",
            "2405:8100::/32",
            "2405:b500::/32",
            "2606:4700::/32",
            "2803:f800::/32",
            "2c0f:f248::/32",
            "2a06:98c0::/29"
        )

        val DEFAULT_BLOCKED_CIDRS = listOf(
            "127.0.0.0/8",
            "::1/128",
            "93.158.213.92/32",
            "102.223.180.235/32",
            "23.134.88.6/32",
            "185.243.218.213/32",
            "208.83.20.20/32",
            "91.216.110.52/32",
            "83.146.97.90/32",
            "23.157.120.14/32",
            "185.102.219.163/32",
            "163.172.29.130/32",
            "156.234.201.18/32",
            "209.141.59.16/32",
            "34.94.213.23/32",
            "192.3.165.191/32",
            "130.61.55.93/32",
            "109.201.134.183/32",
            "95.31.11.224/32",
            "83.102.180.21/32",
            "192.95.46.115/32",
            "198.100.149.66/32",
            "95.216.74.39/32",
            "51.68.174.87/32",
            "37.187.111.136/32",
            "51.15.79.209/32",
            "45.92.156.182/32",
            "49.12.76.8/32",
            "5.196.89.204/32",
            "62.233.57.13/32",
            "45.9.60.30/32",
            "35.227.12.84/32",
            "179.43.155.30/32",
            "94.243.222.100/32",
            "207.241.231.226/32",
            "207.241.226.111/32",
            "51.159.54.68/32",
            "82.65.115.10/32",
            "95.217.167.10/32",
            "86.57.161.157/32",
            "83.31.30.230/32",
            "94.103.87.87/32",
            "160.119.252.41/32",
            "193.42.111.57/32",
            "80.240.22.46/32",
            "107.189.31.134/32",
            "104.244.79.114/32",
            "85.239.33.28/32",
            "61.222.178.254/32",
            "38.7.201.142/32",
            "51.81.222.188/32",
            "103.196.36.31/32",
            "23.153.248.2/32",
            "73.170.204.100/32",
            "176.31.250.174/32",
            "149.56.179.233/32",
            "212.237.53.230/32",
            "185.68.21.244/32",
            "82.156.24.219/32",
            "216.201.9.155/32",
            "51.15.41.46/32",
            "85.206.172.159/32",
            "104.244.77.87/32",
            "37.27.4.53/32",
            "192.3.165.198/32",
            "15.204.205.14/32",
            "103.122.21.50/32",
            "104.131.98.232/32",
            "173.249.201.201/32",
            "23.254.228.89/32",
            "5.102.159.190/32",
            "65.130.205.148/32",
            "119.28.71.45/32",
            "159.69.65.157/32",
            "160.251.78.190/32",
            "107.189.7.143/32",
            "159.65.224.91/32",
            "185.217.199.21/32",
            "91.224.92.110/32",
            "161.97.67.210/32",
            "51.15.3.74/32",
            "209.126.11.233/32",
            "37.187.95.112/32",
            "167.99.185.219/32",
            "144.91.88.22/32",
            "88.99.2.212/32",
            "37.59.48.81/32",
            "95.179.130.187/32",
            "51.15.26.25/32",
            "192.9.228.30/32"
        )
    }
}

/**
 * 8-byte framed UDP-over-TCP packet.
 */
data class UdpOverTcpFrame(
    val sessionId: ByteArray,
    val streamTag: ByteArray,
    val payload: ByteArray
) {
    fun encode(): ByteArray {
        val buf = ByteBuffer.allocate(8 + payload.size)
        buf.put(sessionId, 0, 6)
        buf.put(streamTag, 0, 2)
        buf.put(payload)
        return buf.array()
    }

    companion object {
        fun decode(src: ByteArray): UdpOverTcpFrame? {
            if (src.size < 8) return null
            val sessionId = src.copyOfRange(0, 6)
            val streamTag = src.copyOfRange(6, 8)
            val payload = src.copyOfRange(8, src.size)
            return UdpOverTcpFrame(sessionId, streamTag, payload)
        }

        fun buildResponse(streamTag: ByteArray, datagram: ByteArray): ByteArray {
            val buf = ByteBuffer.allocate(2 + datagram.size)
            buf.put(streamTag, 0, 2)
            buf.put(datagram)
            return buf.array()
        }

        fun decodeResponse(src: ByteArray): Pair<ByteArray, ByteArray>? {
            if (src.size < 2) return null
            val tag = src.copyOfRange(0, 2)
            val datagram = src.copyOfRange(2, src.size)
            return Pair(tag, datagram)
        }

        fun channelKey(destination: String, sessionId: ByteArray, streamTag: ByteArray): String {
            val hexSession = sessionId.joinToString("") { "%02x".format(it) }
            val hexTag = streamTag.joinToString("") { "%02x".format(it) }
            return "$destination:$hexSession$hexTag"
        }
    }

    override fun equals(other: Any?): Boolean {
        if (this === other) return true
        if (javaClass != other?.javaClass) return false
        other as UdpOverTcpFrame
        return sessionId.contentEquals(other.sessionId) &&
                streamTag.contentEquals(other.streamTag) &&
                payload.contentEquals(other.payload)
    }

    override fun hashCode(): Int {
        var result = sessionId.contentHashCode()
        result = 31 * result + streamTag.contentHashCode()
        result = 31 * result + payload.contentHashCode()
        return result
    }
}
