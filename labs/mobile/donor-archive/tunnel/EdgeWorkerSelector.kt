package com.luminet.android.tunnel

data class WorkerEndpoint(
    val domain: String,
    val cleanIp: String,
    val port: Int,
    var latencyMs: Long,
    var packetLossPct: Float
) {
    fun score(): Double = latencyMs.toDouble() + (packetLossPct.toDouble() * 150.0)
}

class EdgeWorkerSelector {
    private val endpoints = mutableListOf<WorkerEndpoint>()

    fun addOrUpdate(domain: String, cleanIp: String, port: Int, latencyMs: Long, loss: Float) {
        val existing = endpoints.find { it.domain == domain && it.cleanIp == cleanIp }
        if (existing != null) {
            existing.latencyMs = latencyMs
            existing.packetLossPct = loss
        } else {
            endpoints.add(WorkerEndpoint(domain, cleanIp, port, latencyMs, loss))
        }
    }

    fun selectBest(): WorkerEndpoint? {
        return endpoints.minByOrNull { it.score() }
    }

    fun synthesizeVlessUri(ep: WorkerEndpoint, uuid: String, sni: String): String {
        return "vless://${uuid}@${ep.cleanIp}:${ep.port}?encryption=none&security=tls&sni=${sni}&type=ws&host=${ep.domain}&path=%2F#LumiNet-Worker"
    }
}
