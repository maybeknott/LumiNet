// Copyright 2024-2026 LumiNet Authors. All Rights Reserved.
package com.luminet.android.tunnel

data class WarpProfile(
    val accountId: String,
    val accessToken: String,
    val privateKey: String,
    val allocatedV4: String = "172.16.0.2",
    val allocatedV6: String = "2606:4700:110:8735:6a4a:2a41:b6b7:b3d3"
)

object WarpAccountClient {
    fun synthesizeWireguardConf(
        profile: WarpProfile,
        endpoint: String = "engage.cloudflareclient.com:2408",
        peerPubKey: String = "bmXOC+F1FxEMF9dyiK2H5/1SUtzH0JuVo51h2wPfgyo="
    ): String {
        return """
[Interface]
PrivateKey = \${profile.privateKey}
Address = \${profile.allocatedV4}/32, \${profile.allocatedV6}/128
DNS = 1.1.1.1, 2606:4700:4700::1111

[Peer]
PublicKey = $peerPubKey
Endpoint = $endpoint
AllowedIPs = 0.0.0.0/0, ::/0
PersistentKeepalive = 25
""".trimIndent()
    }
}
