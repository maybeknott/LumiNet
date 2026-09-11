package com.luminet.android.tunnel

import kotlin.math.abs

enum class AndroidCensorshipAnomaly {
    TCP_RST_INJECTION,
    DNS_POLLUTION,
    UDP_BLACKHOLE,
    SNI_RESET
}

data class AndroidInterferenceReport(
    val anomaly: AndroidCensorshipAnomaly,
    val confidence: Float,
    val details: String
)

class CensorshipAnomalyProber {
    fun probeTcpRst(rstReceived: Boolean, rstTtl: Int, synAckTtl: Int): AndroidInterferenceReport? {
        if (!rstReceived) return null
        val diff = abs(rstTtl - synAckTtl)
        val conf = if (diff >= 5) 0.95f else 0.65f
        return AndroidInterferenceReport(
            AndroidCensorshipAnomaly.TCP_RST_INJECTION,
            conf,
            "TCP RST injection detected with TTL delta: $diff"
        )
    }

    fun probeDnsPollution(domain: String, ips: List<String>): AndroidInterferenceReport? {
        for (ip in ips) {
            if (ip.startsWith("127.") || ip.startsWith("10.") || ip.startsWith("192.168.")) {
                return AndroidInterferenceReport(
                    AndroidCensorshipAnomaly.DNS_POLLUTION,
                    0.95f,
                    "Domain $domain resolved to reserved address $ip"
                )
            }
        }
        return null
    }

    fun probeUdpDrop(sent: Int, recvd: Int): AndroidInterferenceReport? {
        if (sent < 5) return null
        val loss = (sent - recvd).toFloat() / sent.toFloat()
        if (loss >= 0.90f) {
            return AndroidInterferenceReport(
                AndroidCensorshipAnomaly.UDP_BLACKHOLE,
                0.92f,
                "Severe UDP loss: ${(loss * 100).toInt()}%"
            )
        }
        return null
    }
}
