package com.luminet.android.tunnel

import java.net.InetAddress
import java.util.concurrent.ConcurrentHashMap

enum class AndroidMeshMode {
    DIRECT,
    DERP_RELAY
}

data class AndroidMeshPeer(
    val peerId: String,
    val publicKeyHex: String,
    val virtualIp: String,
    val allowedIps: List<String>,
    val endpoints: List<String>,
    val derpRegionId: Int,
    val lastHandshakeMs: Long,
    val isExitNode: Boolean
)

class MeshWireguardCoordinator(
    val localPeerId: String,
    val localVirtualIp: String
) {
    private val peers = ConcurrentHashMap<String, AndroidMeshPeer>()
    private val derpRelays = ConcurrentHashMap<Int, String>()

    fun registerDerpRelay(regionId: Int, host: String) {
        derpRelays[regionId] = host
    }

    fun registerPeer(peer: AndroidMeshPeer) {
        peers[peer.peerId] = peer
    }

    fun selectBestEndpoint(peerId: String, nowMs: Long): Pair<AndroidMeshMode, String>? {
        val peer = peers[peerId] ?: return null
        val isRecent = (nowMs - peer.lastHandshakeMs) < 180_000

        return if (isRecent && peer.endpoints.isNotEmpty()) {
            Pair(AndroidMeshMode.DIRECT, peer.endpoints.first())
        } else if (derpRelays.containsKey(peer.derpRegionId)) {
            Pair(AndroidMeshMode.DERP_RELAY, derpRelays[peer.derpRegionId]!!)
        } else if (peer.endpoints.isNotEmpty()) {
            Pair(AndroidMeshMode.DIRECT, peer.endpoints.first())
        } else {
            null
        }
    }

    fun lookupRoute(destIp: String): String? {
        // Exact virtual IP match
        peers.values.find { it.virtualIp == destIp }?.let { return it.peerId }

        // Subnet prefix match
        for (peer in peers.values) {
            for (cidr in peer.allowedIps) {
                if (matchesCidr(destIp, cidr)) {
                    return peer.peerId
                }
            }
        }
        return null
    }

    fun generatePeerConfig(peerId: String): String {
        val peer = peers[peerId] ?: throw IllegalArgumentException("Peer not found")
        val allowed = if (peer.allowedIps.isEmpty()) "${peer.virtualIp}/32" else peer.allowedIps.joinToString(", ")
        val endpointLine = if (peer.endpoints.isNotEmpty()) "Endpoint = ${peer.endpoints.first()}\nPersistentKeepalive = 25\n" else ""

        return """
            |[Peer]
            |PublicKey = ${peer.publicKeyHex}
            |AllowedIPs = $allowed
            |$endpointLine
        """.trimMargin().trim()
    }

    private fun matchesCidr(ipStr: String, cidrStr: String): Boolean {
        return try {
            val parts = cidrStr.split("/")
            if (parts.size != 2) return false
            val netAddr = InetAddress.getByName(parts[0]).address
            val targetAddr = InetAddress.getByName(ipStr).address
            val prefix = parts[1].toInt()
            if (prefix == 0) return true

            var matched = true
            var bits = prefix
            for (i in netAddr.indices) {
                if (bits >= 8) {
                    if (netAddr[i] != targetAddr[i]) { matched = false; break }
                    bits -= 8
                } else if (bits > 0) {
                    val mask = (0xFF shl (8 - bits)) and 0xFF
                    if ((netAddr[i].toInt() and mask) != (targetAddr[i].toInt() and mask)) { matched = false; break }
                    bits = 0
                } else break
            }
            matched
        } catch (e: Exception) {
            false
        }
    }
}
