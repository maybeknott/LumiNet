// Copyright 2024-2026 LumiNet Authors. All Rights Reserved.
package com.luminet.android.tunnel

class PeerAclMatrix(private val defaultAllow: Boolean = true) {
    private val aclRules = mutableMapOf<String, MutableMap<String, Boolean>>()
    private val lock = Any()

    fun setRule(source: String, target: String, allowed: Boolean) = synchronized(lock) {
        aclRules.getOrPut(source) { mutableMapOf() }[target] = allowed
    }

    fun isAllowed(source: String, target: String): Boolean = synchronized(lock) {
        aclRules[source]?.get(target) ?: defaultAllow
    }
}
