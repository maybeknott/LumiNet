package com.luminet.android.tunnel

data class AndroidEgressLink(
    val id: String,
    var rttMs: Long,
    var isActive: Boolean,
    var sentBytes: Long = 0L
)

class MultipathGatewayCoordinator {
    private val links = mutableMapOf<String, AndroidEgressLink>()
    private val keys = mutableListOf<String>()
    private var cursor = 0

    fun registerLink(link: AndroidEgressLink) {
        if (!links.containsKey(link.id)) {
            keys.add(link.id)
        }
        links[link.id] = link
    }

    fun routePacket(bytes: Long): String? {
        val active = keys.filter { links[it]?.isActive == true }
        if (active.isEmpty()) return null
        val selected = active[cursor % active.size]
        cursor++
        links[selected]?.let { it.sentBytes += bytes }
        return selected
    }

    fun setLinkActive(id: String, active: Boolean) {
        links[id]?.isActive = active
    }
}
