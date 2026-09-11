// Copyright 2024-2026 LumiNet Authors. All Rights Reserved.
package com.luminet.android.tunnel

data class ZeroTrustResource(
    val id: String,
    val name: String,
    val networkCidr: String,
    val mappedIp: String,
    val allowedPermissionMask: Int
)

class ZeroTrustRouteTable {
    private val resources = mutableMapOf<String, ZeroTrustResource>()
    private val ipToResource = mutableMapOf<String, String>()
    private val lock = Any()

    fun registerResource(res: ZeroTrustResource) = synchronized(lock) {
        resources[res.id] = res
        ipToResource[res.mappedIp] = res.id
    }

    fun lookupByIp(ip: String): ZeroTrustResource? = synchronized(lock) {
        val id = ipToResource[ip] ?: return null
        resources[id]
    }

    fun evaluateAccess(ip: String, clientPermissions: Int): Boolean = synchronized(lock) {
        val res = lookupByIp(ip) ?: return false
        (res.allowedPermissionMask and clientPermissions) == res.allowedPermissionMask
    }
}
