package com.luminet.android.tunnel

data class AndroidProtocolProfile(
    val name: String,
    val capabilities: Set<String>,
    val score: Int
)

class ProtocolCapabilityMatrix {
    val profiles = mutableListOf<AndroidProtocolProfile>()

    init {
        profiles.add(AndroidProtocolProfile("Hysteria2", setOf("multipath_udp", "padding", "tls_spoof"), 95))
        profiles.add(AndroidProtocolProfile("VLESS-Reality", setOf("tls_spoof", "replay_defense", "padding"), 92))
        profiles.add(AndroidProtocolProfile("Trojan-SNI-Fragment", setOf("sni_fragmentation", "tls_spoof"), 88))
    }

    fun recommend(required: Set<String>): AndroidProtocolProfile? {
        return profiles
            .filter { it.capabilities.containsAll(required) }
            .maxByOrNull { it.score }
    }
}
