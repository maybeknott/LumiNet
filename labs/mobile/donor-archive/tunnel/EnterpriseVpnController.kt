package com.luminet.android.tunnel

enum class EnterpriseRole {
    STANDARD_USER,
    ADMIN,
    AUDITOR
}

data class EnterpriseTenant(
    val orgId: String,
    val name: String,
    val virtualSubnet: String,
    val maxUsers: Int
)

data class EnterpriseUserProfile(
    val username: String,
    val orgId: String,
    val role: EnterpriseRole,
    val token: String,
    val virtualIp: String,
    val allowedRoutes: List<String>,
    var isActive: Boolean = true
)

class EnterpriseVpnController {
    private val orgs = mutableMapOf<String, EnterpriseTenant>()
    private val users = mutableMapOf<String, EnterpriseUserProfile>() // keyed by token

    fun registerTenant(tenant: EnterpriseTenant) {
        orgs[tenant.orgId] = tenant
    }

    fun registerUser(user: EnterpriseUserProfile): Boolean {
        val org = orgs[user.orgId] ?: return false
        val activeCount = users.values.count { it.orgId == user.orgId && it.isActive }
        if (activeCount >= org.maxUsers) return false

        users[user.token] = user
        return true
    }

    fun authenticate(token: String): EnterpriseUserProfile? {
        val u = users[token] ?: return null
        return if (u.isActive) u else null
    }

    fun canAccessRoute(token: String, destinationIp: String): Boolean {
        val u = authenticate(token) ?: return false
        if (u.role == EnterpriseRole.ADMIN) return true

        for (route in u.allowedRoutes) {
            if (route == "0.0.0.0/0") return true
            if (route.contains("/")) {
                val parts = route.split("/")
                val netStr = parts[0]
                val prefixLen = parts[1].toIntOrNull() ?: 32
                if (matchesCidr(destinationIp, netStr, prefixLen)) {
                    return true
                }
            } else if (route == destinationIp) {
                return true
            }
        }
        return false
    }

    fun revokeUser(token: String): Boolean {
        val u = users[token] ?: return false
        u.isActive = false
        return true
    }

    fun activeUserCount(): Int = users.values.count { it.isActive }

    private fun matchesCidr(ip: String, net: String, prefix: Int): Boolean {
        val ipVal = ipToLong(ip) ?: return false
        val netVal = ipToLong(net) ?: return false
        val mask = if (prefix == 0) 0L else (-1L shl (32 - prefix)) and 0xFFFFFFFFL
        return (ipVal and mask) == (netVal and mask)
    }

    private fun ipToLong(ip: String): Long? {
        val parts = ip.split(".")
        if (parts.size != 4) return null
        var res = 0L
        for (p in parts) {
            val v = p.toLongOrNull() ?: return null
            if (v < 0 || v > 255) return null
            res = (res shl 8) or v
        }
        return res
    }
}
