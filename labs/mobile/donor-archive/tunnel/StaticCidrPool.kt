// Copyright 2024-2026 LumiNet Authors. All Rights Reserved.
package com.luminet.android.tunnel

data class StaticClientRecord(
    val clientId: String,
    val allocatedIp: String,
    val publicKey: String,
    var isRevoked: Boolean = false
)

class StaticCidrPool(private val basePrefix: String = "10.66.0.") {
    private var nextHost = 2
    private val allocated = mutableMapOf<String, StaticClientRecord>()
    private val revokedKeys = mutableSetOf<String>()
    private val lock = Any()

    fun allocateClient(clientId: String, publicKey: String): StaticClientRecord? = synchronized(lock) {
        if (nextHost >= 254) return null
        val ip = "$basePrefix$nextHost"
        nextHost++

        val record = StaticClientRecord(clientId, ip, publicKey)
        allocated[ip] = record
        record
    }

    fun revokeClient(ip: String): Boolean = synchronized(lock) {
        val client = allocated[ip] ?: return false
        client.isRevoked = true
        revokedKeys.add(client.publicKey)
        true
    }

    fun isKeyRevoked(publicKey: String): Boolean = synchronized(lock) {
        revokedKeys.contains(publicKey)
    }
}
