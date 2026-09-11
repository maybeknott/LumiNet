// Copyright 2024-2026 LumiNet Authors. All Rights Reserved.
package com.luminet.android.tunnel

data class InterceptRule(
    val headerName: String,
    val headerValueExact: String,
    val targetLocalAddress: String
)

class HeaderInterceptRouter {
    private val rules = mutableListOf<InterceptRule>()
    private val lock = Any()

    fun addRule(name: String, value: String, target: String) = synchronized(lock) {
        rules.add(InterceptRule(name.lowercase(), value, target))
    }

    fun evaluateHeaders(headers: Map<String, String>): String? = synchronized(lock) {
        for (rule in rules) {
            for ((k, v) in headers) {
                if (k.lowercase() == rule.headerName && v == rule.headerValueExact) {
                    return rule.targetLocalAddress
                }
            }
        }
        null
    }
}
