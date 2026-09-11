package com.luminet.android.tunnel

enum class AndroidUserRole {
    GUEST,
    OPERATOR,
    ADMIN
}

class EnterpriseAccessInterceptor {
    private val routeRules = mutableMapOf<String, AndroidUserRole>()
    var auditCount = 0

    fun protectRoute(prefix: String, minRole: AndroidUserRole) {
        routeRules[prefix] = minRole
    }

    fun authorize(path: String, role: AndroidUserRole): Boolean {
        auditCount++
        for ((prefix, minRole) in routeRules) {
            if (path.startsWith(prefix)) {
                if (role < minRole) return false
            }
        }
        return true
    }
}
