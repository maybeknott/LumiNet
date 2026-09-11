// Copyright 2024-2026 LumiNet Authors. All Rights Reserved.
package com.luminet.android.tunnel

data class KillswitchRules(
    val vpnInterface: String = "tun0",
    val vpnPort: Int = 51820,
    val vpnServerIp: String,
    val allowedSubnets: List<String> = listOf("127.0.0.1/8", "10.0.0.0/8", "192.168.0.0/16"),
    val blockDnsLeaks: Boolean = true
) {
    fun generateIptablesRules(): List<String> {
        val rules = mutableListOf(
            "iptables -F OUTPUT",
            "iptables -P OUTPUT DROP",
            "iptables -A OUTPUT -o lo -j ACCEPT",
            "iptables -A OUTPUT -o $vpnInterface -j ACCEPT",
            "iptables -A OUTPUT -d $vpnServerIp -p udp --dport $vpnPort -j ACCEPT"
        )
        for (subnet in allowedSubnets) {
            rules.add("iptables -A OUTPUT -d $subnet -j ACCEPT")
        }
        if (blockDnsLeaks) {
            rules.add("iptables -A OUTPUT -o ! $vpnInterface -p udp --dport 53 -j REJECT")
            rules.add("iptables -A OUTPUT -o ! $vpnInterface -p tcp --dport 53 -j REJECT")
        }
        return rules
    }
}
