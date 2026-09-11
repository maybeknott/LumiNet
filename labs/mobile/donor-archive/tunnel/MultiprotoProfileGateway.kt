package com.luminet.android.tunnel

data class AndroidGatewayEndpoint(
    val endpointId: String,
    val protocol: ClientTunnelProtocol,
    val host: String,
    val port: Int,
    var pingMs: Int,
    var isHealthy: Boolean = true
)

class MultiprotoProfileGateway {
    private val endpoints = mutableMapOf<String, AndroidGatewayEndpoint>()
    private var failoverChain = listOf<String>()
    private val transpiler = OvpnConfigTranspiler()
    private val relayAggregator = PublicRelayAggregator()

    fun registerEndpoint(ep: AndroidGatewayEndpoint) {
        endpoints[ep.endpointId] = ep
    }

    fun setFailoverChain(chain: List<String>) {
        failoverChain = chain
    }

    fun resolveActiveRoute(): AndroidGatewayEndpoint? {
        for (id in failoverChain) {
            val ep = endpoints[id]
            if (ep != null && ep.isHealthy) {
                return ep
            }
        }
        return endpoints.values.firstOrNull { it.isHealthy }
    }

    fun importRelays(relays: List<AndroidRelayNode>) {
        for (r in relays) {
            relayAggregator.ingestNode(r)
            val proto = when (r.protocol.lowercase()) {
                "shadowsocks" -> ClientTunnelProtocol.SHADOWSOCKS_2022
                "vless" -> ClientTunnelProtocol.VLESS
                "wireguard" -> ClientTunnelProtocol.AMNEZIA_WG
                else -> ClientTunnelProtocol.MASQUE
            }
            registerEndpoint(AndroidGatewayEndpoint(
                endpointId = r.nodeId,
                protocol = proto,
                host = r.host,
                port = r.port,
                pingMs = r.pingMs,
                isHealthy = r.isAlive
            ))
        }
    }

    fun transpileAndRegisterOvpn(endpointId: String, rawOvpn: String): AndroidGatewayEndpoint? {
        val parsed = transpiler.transpile(rawOvpn) ?: return null
        val ep = AndroidGatewayEndpoint(
            endpointId = endpointId,
            protocol = ClientTunnelProtocol.AMNEZIA_WG,
            host = parsed.remoteHost,
            port = parsed.remotePort,
            pingMs = 50,
            isHealthy = true
        )
        registerEndpoint(ep)
        return ep
    }
}
