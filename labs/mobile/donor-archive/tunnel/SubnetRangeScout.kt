package com.luminet.android.tunnel

data class SubnetScoutTarget(
    val ip: String,
    val rttMs: Long,
    val isClean: Boolean
)

data class SubnetScoutReport(
    val subnet: String,
    val totalTested: Int,
    val cleanCount: Int,
    val bestTargets: List<SubnetScoutTarget>
)

class SubnetRangeScout(
    val maxRttMsThreshold: Long = 200L
) {
    fun scout(baseSubnet: String, count: Int = 10): SubnetScoutReport {
        val targets = mutableListOf<SubnetScoutTarget>()
        var clean = 0
        for (i in 1..count.coerceAtMost(254)) {
            val ip = "$baseSubnet.$i"
            val rtt = (20L + (i * 11L) % 150L)
            val isClean = rtt <= maxRttMsThreshold
            if (isClean) clean++
            targets.add(SubnetScoutTarget(ip, rtt, isClean))
        }
        val best = targets.sortedBy { it.rttMs }.take(5)
        return SubnetScoutReport(
            subnet = "$baseSubnet.0/24",
            totalTested = targets.size,
            cleanCount = clean,
            bestTargets = best
        )
    }
}
