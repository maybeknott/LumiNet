package com.luminet.android.tunnel

enum class AccessDecision {
    Allowed, Throttled, Banned
}

data class ClientRecord(
    var failures: Int = 0,
    var tokens: Double,
    var lastAccessUnix: Long,
    var bannedUntilUnix: Long = 0
)

class ClientBanSupervisor(
    val maxFailures: Int = 5,
    val banDurationSecs: Long = 300,
    val bucketCapacity: Double = 10.0,
    val refillRatePerSec: Double = 1.0
) {
    private val clients = mutableMapOf<String, ClientRecord>()

    fun checkAccess(ip: String, nowUnix: Long): Pair<AccessDecision, Long> {
        val rec = clients.getOrPut(ip) {
            ClientRecord(tokens = bucketCapacity, lastAccessUnix = nowUnix)
        }

        if (rec.bannedUntilUnix > nowUnix) {
            return Pair(AccessDecision.Banned, rec.bannedUntilUnix - nowUnix)
        }

        val elapsed = (nowUnix - rec.lastAccessUnix).coerceAtLeast(0)
        rec.tokens = (rec.tokens + elapsed * refillRatePerSec).coerceAtMost(bucketCapacity)
        rec.lastAccessUnix = nowUnix

        if (rec.tokens < 1.0) {
            return Pair(AccessDecision.Throttled, 0)
        }

        rec.tokens -= 1.0
        return Pair(AccessDecision.Allowed, 0)
    }

    fun recordAuthResult(ip: String, success: Boolean, nowUnix: Long) {
        val rec = clients.getOrPut(ip) {
            ClientRecord(tokens = bucketCapacity, lastAccessUnix = nowUnix)
        }
        if (success) {
            rec.failures = 0
        } else {
            rec.failures++
            if (rec.failures >= maxFailures) {
                rec.bannedUntilUnix = nowUnix + banDurationSecs
            }
        }
    }

    fun unban(ip: String) {
        clients[ip]?.let {
            it.bannedUntilUnix = 0
            it.failures = 0
        }
    }

    fun isBanned(ip: String, nowUnix: Long): Boolean {
        return (clients[ip]?.bannedUntilUnix ?: 0) > nowUnix
    }
}
