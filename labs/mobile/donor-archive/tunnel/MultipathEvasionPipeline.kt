package com.luminet.android.tunnel

class MultipathEvasionPipeline(
    tunnelId: String,
    mode: BondingMode,
    queueNum: Int,
    mark: Long,
    region: AndroidCensorshipRegion
) {
    val tunnel = MultipathUdpTunnel(tunnelId, mode)
    val scrambler = NfqueuePacketScrambler(queueNum, mark)
    val profile: AndroidEvasionProfile

    init {
        val synth = CensorshipProfileSynthesizer()
        profile = synth.getProfile(region)
        if (profile.tcpMssClamp < 1200) {
            scrambler.ttlHopLimit = 48
        } else {
            scrambler.ttlHopLimit = 64
        }
    }

    fun registerPath(pathId: Int, local: String, remote: String, weight: Int) {
        tunnel.addPath(PathMetrics(pathId, local, remote, weight = weight))
    }

    fun prepareOutboundPacket(dest: String, payload: ByteArray): Pair<Int, ByteArray>? {
        // 1. Scramble/inspect
        scrambler.processIpPacket(dest, payload)

        // 2. Select path
        val pathId = tunnel.selectPathForEgress() ?: return null

        // 3. Encapsulate
        val frame = tunnel.encapsulate(pathId, payload) ?: return null
        return Pair(pathId, frame)
    }
}
