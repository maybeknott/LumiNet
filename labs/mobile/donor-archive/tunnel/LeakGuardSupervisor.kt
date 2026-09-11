package com.luminet.android.tunnel

data class AndroidLeakReport(
    val leakType: String,
    val targetIp: String,
    val iface: String
)

class LeakGuardSupervisor(
    private val tunnelIface: String,
    private val allowedDns: List<String>,
    private val blockIpv6: Boolean = true
) {
    var killswitchActive: Boolean = true
    private val leaks = mutableListOf<AndroidLeakReport>()

    fun validateOutbound(dstIp: String, dstPort: Int, iface: String): Boolean {
        if (!killswitchActive) return true

        if (iface != tunnelIface) {
            // DNS leak check
            if (dstPort in listOf(53, 853, 5353)) {
                if (!allowedDns.contains(dstIp)) {
                    leaks.add(AndroidLeakReport("DNS_LEAK", dstIp, iface))
                    return false
                }
            }

            // IPv6 leak check
            if (blockIpv6 && dstIp.contains(":")) {
                leaks.add(AndroidLeakReport("IPV6_LEAK", dstIp, iface))
                return false
            }
        }

        return true
    }

    fun totalLeaks(): Int = leaks.size
}
