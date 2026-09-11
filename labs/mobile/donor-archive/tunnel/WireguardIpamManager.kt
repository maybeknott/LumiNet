package com.luminet.android.tunnel

data class WireguardPeer(
    val publicKey: String,
    val assignedIp: String,
    val allowedIps: List<String>,
    var endpoint: String? = null,
    var enabled: Boolean = true
)

class WireguardIpamManager(val subnetPrefix: String, val listenPort: Int) {
    private var nextSuffix: Int = 2
    val serverIp: String = "$subnetPrefix.1"
    private val peers = HashMap<String, WireguardPeer>()
    private val ipToKey = HashMap<String, String>()

    init {
        val parts = subnetPrefix.split(".")
        if (parts.size != 3) {
            throw IllegalArgumentException("Subnet prefix must have 3 octets, e.g. 10.14.0")
        }
    }

    fun allocatePeer(publicKey: String): WireguardPeer {
        peers[publicKey]?.let { return it }

        if (nextSuffix >= 254) {
            throw IllegalStateException("Subnet exhausted")
        }

        val assignedIp = "$subnetPrefix.$nextSuffix"
        nextSuffix++

        val peer = WireguardPeer(
            publicKey = publicKey,
            assignedIp = assignedIp,
            allowedIps = listOf("$assignedIp/32")
        )

        peers[publicKey] = peer
        ipToKey[assignedIp] = publicKey
        return peer
    }

    fun releasePeer(publicKey: String) {
        val peer = peers.remove(publicKey) ?: throw NoSuchElementException("Peer not found")
        ipToKey.remove(peer.assignedIp)
    }

    fun generateServerConfig(serverPrivateKey: String): String {
        val lines = ArrayList<String>()
        lines.add("[Interface]")
        lines.add("Address = $serverIp/24")
        lines.add("ListenPort = $listenPort")
        lines.add("PrivateKey = $serverPrivateKey")
        lines.add("")

        for (peer in peers.values) {
            if (peer.enabled) {
                lines.add("[Peer]")
                lines.add("PublicKey = ${peer.publicKey}")
                lines.add("AllowedIPs = ${peer.allowedIps.joinToString(", ")}")
                peer.endpoint?.let { lines.add("Endpoint = $it") }
                lines.add("")
            }
        }

        return lines.joinToString("\n")
    }

    fun generateClientConfig(
        peerPublicKey: String,
        peerPrivateKey: String,
        serverPublicKey: String,
        serverEndpoint: String
    ): String {
        val peer = peers[peerPublicKey] ?: throw NoSuchElementException("Peer not registered")

        val lines = ArrayList<String>()
        lines.add("[Interface]")
        lines.add("Address = ${peer.assignedIp}/32")
        lines.add("PrivateKey = $peerPrivateKey")
        lines.add("DNS = 1.1.1.1")
        lines.add("")

        lines.add("[Peer]")
        lines.add("PublicKey = $serverPublicKey")
        lines.add("Endpoint = $serverEndpoint")
        lines.add("AllowedIPs = 0.0.0.0/0, ::/0")
        lines.add("PersistentKeepalive = 25")

        return lines.joinToString("\n")
    }
}
