// Copyright 2024-2026 LumiNet Authors. All Rights Reserved.
package com.luminet.android.tunnel

data class WireguardPeerRecord(
    val publicKey: String,
    val presharedKey: String,
    val allocatedIpv4: String,
    val allocatedIpv6: String,
    val name: String,
    val enabled: Boolean = true
)

class WireguardPeerAllocator(
    private val v4BasePrefix: String = "10.88.0.",
    private val v6BasePrefix: String = "fd00:88::"
) {
    private var nextHostId = 2
    private val peers = mutableMapOf<String, WireguardPeerRecord>()
    private val lock = Any()

    fun allocatePeer(pubKey: String, name: String): WireguardPeerRecord = synchronized(lock) {
        val existing = peers[pubKey]
        if (existing != null) return existing

        val v4 = "$v4BasePrefix$nextHostId"
        val v6 = "$v6BasePrefix$nextHostId"
        nextHostId++

        val record = WireguardPeerRecord(
            publicKey = pubKey,
            presharedKey = "mockPskBase64==",
            allocatedIpv4 = v4,
            allocatedIpv6 = v6,
            name = name
        )
        peers[pubKey] = record
        record
    }

    fun formatClientConfig(
        rec: WireguardPeerRecord,
        clientPrivKey: String,
        endpoint: String,
        serverPubKey: String,
        dns: String = "1.1.1.1"
    ): String {
        return """
[Interface]
PrivateKey = $clientPrivKey
Address = \${rec.allocatedIpv4}/32, \${rec.allocatedIpv6}/128
DNS = $dns

[Peer]
PublicKey = $serverPubKey
PresharedKey = \${rec.presharedKey}
Endpoint = $endpoint
AllowedIPs = 0.0.0.0/0, ::/0
PersistentKeepalive = 25
""".trimIndent()
    }
}
