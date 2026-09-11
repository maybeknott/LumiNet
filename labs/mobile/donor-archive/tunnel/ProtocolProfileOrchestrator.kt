package com.luminet.android.tunnel

enum class ClientTunnelProtocol {
    AMNEZIA_WG,
    VLESS,
    SHADOWSOCKS_2022,
    MASQUE
}

data class ClientProfile(
    val profileId: String,
    val name: String,
    val protocol: ClientTunnelProtocol,
    val endpoint: String,
    val fallbackOrder: Int,
    val configPayload: String
)

class ProtocolProfileOrchestrator {
    private val profiles = mutableMapOf<String, ClientProfile>()
    var activeProfileId: String? = null

    fun addProfile(profile: ClientProfile) {
        profiles[profile.profileId] = profile
        if (activeProfileId == null) {
            activeProfileId = profile.profileId
        }
    }

    fun setActiveProfile(profileId: String): Boolean {
        if (!profiles.containsKey(profileId)) return false
        activeProfileId = profileId
        return true
    }

    fun getActiveProfile(): ClientProfile? {
        val id = activeProfileId ?: return null
        return profiles[id]
    }

    fun getFallbackChain(): List<ClientProfile> {
        return profiles.values.sortedBy { it.fallbackOrder }
    }

    fun totalProfiles(): Int = profiles.size
}
