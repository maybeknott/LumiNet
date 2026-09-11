package com.luminet.android.tunnel

class AdaptiveMtuDiscovery(
    private var minMtu: Int = 1280,
    private var maxMtu: Int = 1500
) {
    var currentProbe: Int = (minMtu + maxMtu) / 2
        private set
    var convergedMtu: Int? = null
        private set

    fun nextProbeSize(): Int = currentProbe

    fun recordResult(size: Int, success: Boolean) {
        if (success) {
            minMtu = size
        } else {
            maxMtu = (size - 1).coerceAtLeast(minMtu)
        }

        if (minMtu >= maxMtu) {
            convergedMtu = minMtu
        } else {
            currentProbe = (minMtu + maxMtu + 1) / 2
        }
    }

    fun optimalMtu(): Int = convergedMtu ?: minMtu

    fun wireguardPayloadMtu(isIpv6: Boolean): Int {
        val overhead = if (isIpv6) 80 else 60
        return (optimalMtu() - overhead).coerceAtLeast(1280)
    }

    fun optimalKeepaliveSecs(): Int = if (optimalMtu() < 1360) 15 else 25
}
