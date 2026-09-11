// Copyright 2024-2026 LumiNet Authors. All Rights Reserved.
package com.luminet.android.tunnel

data class HotspotConfig(
    val downstreamIface: String = "wlan1",
    val upstreamVpnIface: String = "tun0",
    val downstreamSubnet: String = "192.168.43.0/24",
    val clampMssBytes: Int = 1360
)

class HotspotNatRepeater(private val config: HotspotConfig = HotspotConfig()) {
    fun generateIptables(): List<String> {
        return listOf(
            "echo 1 > /proc/sys/net/ipv4/ip_forward",
            "iptables -A FORWARD -i ${config.downstreamIface} -o ${config.upstreamVpnIface} -j ACCEPT",
            "iptables -A FORWARD -i ${config.upstreamVpnIface} -o ${config.downstreamIface} -m state --state RELATED,ESTABLISHED -j ACCEPT",
            "iptables -t nat -A POSTROUTING -s ${config.downstreamSubnet} -o ${config.upstreamVpnIface} -j MASQUERADE",
            "iptables -t mangle -A FORWARD -p tcp --tcp-flags SYN,RST SYN -j TCPMSS --set-mss ${config.clampMssBytes}"
        )
    }
}
