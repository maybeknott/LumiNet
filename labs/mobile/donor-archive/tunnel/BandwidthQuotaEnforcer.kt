// Copyright 2024-2026 LumiNet Authors. All Rights Reserved.
package com.luminet.android.tunnel

enum class QuotaAlertLevel {
    NORMAL,
    WARNING_80,
    EXHAUSTED
}

data class UserBandwidthQuota(
    val userId: String,
    val maxBytes: Long,
    var usedBytes: Long = 0,
    var isActive: Boolean = true
)

class BandwidthQuotaEnforcer {
    private val quotas = mutableMapOf<String, UserBandwidthQuota>()
    private val lock = Any()

    fun registerUser(userId: String, maxBytes: Long) = synchronized(lock) {
        quotas[userId] = UserBandwidthQuota(userId, maxBytes)
    }

    fun recordTraffic(userId: String, bytes: Long): QuotaAlertLevel = synchronized(lock) {
        val q = quotas[userId] ?: return QuotaAlertLevel.EXHAUSTED
        q.usedBytes += bytes
        if (q.usedBytes >= q.maxBytes) {
            q.isActive = false
            QuotaAlertLevel.EXHAUSTED
        } else if (q.usedBytes >= (q.maxBytes * 8) / 10) {
            QuotaAlertLevel.WARNING_80
        } else {
            QuotaAlertLevel.NORMAL
        }
    }

    fun isUserAllowed(userId: String): Boolean = synchronized(lock) {
        quotas[userId]?.isActive == true
    }
}
