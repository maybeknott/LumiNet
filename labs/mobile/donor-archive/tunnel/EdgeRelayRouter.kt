package com.luminet.android.tunnel

import java.net.InetAddress
import java.nio.ByteBuffer

/**
 * Route target request parameters.
 */
data class EdgeRouteTarget(
    val network: String, // "tcp" or "udp"
    val host: String,
    val port: Int,
    val resolvedIp: InetAddress? = null
)

/**
 * Outbound routing decision for serverless edge dispatch.
 */
sealed class EdgeRoutingDecision {
    data class Direct(
        val host: String,
        val port: Int
    ) : EdgeRoutingDecision()

    data class RelayChained(
        val relayHost: String,
        val relayPort: Int,
        val delimiterHeader: String
    ) : EdgeRoutingDecision()
}

/**
 * Edge Serverless Relay Router for Android.
 * Evades Cloudflare loopback blocks by diverting CF target IPs to upstream relays,
 * routes UDP datagrams through relay TCP streams, and supports fallback retries.
 */
class EdgeRelayRouter(
    val relayHosts: List<String> = listOf(
        "relay1.bepass.org",
        "relay2.bepass.org",
        "relay3.bepass.org"
    ),
    val relayPort: Int = 6666,
    val cloudflareCidrs: List<String> = DEFAULT_CF_CIDRS
) {
    private val parsedCidrs = cloudflareCidrs.mapNotNull { RelayCidr.parse(it) }

    fun selectRelayEndpoint(sessionId: Long?): Pair<String, Int> {
        if (relayHosts.isEmpty()) return Pair("127.0.0.1", relayPort)
        val idx = if (sessionId != null) {
            (Math.abs(sessionId) % relayHosts.size).toInt()
        } else {
            0
        }
        return Pair(relayHosts[idx], relayPort)
    }

    fun isCloudflareIp(addr: InetAddress?): Boolean {
        if (addr == null) return false
        return parsedCidrs.any { it.contains(addr) }
    }

    fun decideRoute(target: EdgeRouteTarget, sessionId: Long? = null): EdgeRoutingDecision {
        val netLower = target.network.lowercase()
        val requiresRelay = netLower == "udp" || isCloudflareIp(target.resolvedIp)

        return if (requiresRelay) {
            val (rHost, rPort) = selectRelayEndpoint(sessionId)
            val header = "$netLower@${target.host}$${target.port}\r\n"
            EdgeRoutingDecision.RelayChained(rHost, rPort, header)
        } else {
            EdgeRoutingDecision.Direct(target.host, target.port)
        }
    }

    fun buildFallbackRelayRoute(target: EdgeRouteTarget, sessionId: Long? = null): EdgeRoutingDecision {
        val netLower = target.network.lowercase()
        val (rHost, rPort) = selectRelayEndpoint(sessionId)
        val header = "$netLower@${target.host}$${target.port}\r\n"
        return EdgeRoutingDecision.RelayChained(rHost, rPort, header)
    }

    companion object {
        val DEFAULT_CF_CIDRS = listOf(
            "173.245.48.0/20",
            "103.21.244.0/22",
            "103.22.200.0/22",
            "103.31.4.0/22",
            "141.101.64.0/18",
            "108.162.192.0/18",
            "190.93.240.0/20",
            "188.114.96.0/20",
            "197.234.240.0/22",
            "198.41.128.0/17",
            "162.158.0.0/15",
            "104.16.0.0/13",
            "104.24.0.0/14",
            "172.64.0.0/13",
            "131.0.72.0/22",
            "2400:cb00::/32",
            "2606:4700::/32",
            "2803:f800::/32",
            "2405:b500::/32",
            "2405:8100::/32",
            "2a06:98c0::/29",
            "2c0f:f248::/32"
        )

        fun buildDohAQuery(domain: String): ByteArray {
            val parts = domain.split(".")
            var qnameLen = 1
            for (p in parts) {
                if (p.isNotEmpty()) qnameLen += 1 + p.length
            }

            val buf = ByteBuffer.allocate(12 + qnameLen + 4)
            // Header
            buf.putShort(0x1234.toShort()) // Transaction ID
            buf.putShort(0x0100.toShort()) // Flags
            buf.putShort(1.toShort()) // Questions: 1
            buf.putShort(0.toShort()) // Answers: 0
            buf.putShort(0.toShort()) // Authority: 0
            buf.putShort(0.toShort()) // Additional: 0

            // QNAME
            for (p in parts) {
                if (p.isNotEmpty()) {
                    buf.put(p.length.toByte())
                    buf.put(p.toByteArray(Charsets.UTF_8))
                }
            }
            buf.put(0.toByte()) // Terminate QNAME

            // QTYPE (A = 1) and QCLASS (IN = 1)
            buf.putShort(1.toShort())
            buf.putShort(1.toShort())

            return buf.array()
        }
    }
}
