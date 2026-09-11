// Copyright 2024-2026 LumiNet Authors. All Rights Reserved.
package com.luminet.android.tunnel

data class IdentitySessionData(
    val email: String,
    val domain: String,
    val groups: Set<String>
)

data class RoutePolicyRule(
    val pathPrefix: String,
    val allowedDomains: Set<String>,
    val requiredGroups: Set<String>
)

class IdentityPolicyEvaluator {
    private val policies = mutableListOf<RoutePolicyRule>()
    private val lock = Any()

    fun addPolicy(rule: RoutePolicyRule) = synchronized(lock) {
        policies.add(rule)
    }

    fun isAuthorized(path: String, session: IdentitySessionData): Boolean = synchronized(lock) {
        for (policy in policies) {
            if (path.startsWith(policy.pathPrefix)) {
                if (policy.allowedDomains.isNotEmpty() && !policy.allowedDomains.contains(session.domain)) {
                    return false
                }
                if (policy.requiredGroups.isNotEmpty() && policy.requiredGroups.none { session.groups.contains(it) }) {
                    return false
                }
                return true
            }
        }
        false
    }
}
