package com.luminet.android.tunnel

class AdaptiveOutboundCoordinator(
    defaultPolicy: AndroidOutboundPolicy = AndroidOutboundPolicy.Direct,
    failoverThreshold: Int = 3,
    sharedSecret: ByteArray,
    decoyHost: String,
    maxCdnLatency: Long = 300
) {
    val router = MultiOutboundRouter(defaultPolicy)
    val watcher = ProviderFailoverWatcher(failoverThreshold)
    val masquerader = CamouflageStreamMasquerader(sharedSecret, decoyHost)
    val cdnSorter = EdgeCdnPoolSorter(maxCdnLatency)
    var totalDispatched: Long = 0
        private set

    fun routeAndPrepareOutbound(
        targetDomain: String,
        userId: ByteArray
    ): Triple<AndroidOutboundPolicy, String?, ByteArray> {
        totalDispatched++
        val policy = router.matchTarget(targetDomain)
        val bestIp = cdnSorter.bestIp()
        val preamble = masquerader.generatePreamble(userId)
        return Triple(policy, bestIp, preamble)
    }

    fun handleInboundProbe(preamble: ByteArray): AndroidProbeAction {
        return masquerader.inspectInboundStream(preamble)
    }
}
