package com.luminet.android.tunnel

/**
 * Token bucket rate limiter.
 */
class TokenBucketLimiter(
    val rate: Double,
    val capacity: Double
) {
    private var tokens: Double = capacity
    private var lastRefillMs: Long = System.currentTimeMillis()
    private val lock = Any()

    fun allow(): Boolean = take(1.0)

    fun take(n: Double): Boolean {
        synchronized(lock) {
            val now = System.currentTimeMillis()
            val elapsedSec = (now - lastRefillMs).toDouble() / 1000.0
            lastRefillMs = now

            tokens = (tokens + elapsedSec * rate).coerceAtMost(capacity)

            return if (tokens >= n) {
                tokens -= n
                true
            } else {
                false
            }
        }
    }
}

/**
 * Multi-account quota and rate-limit coordinator.
 */
class AccountQuotaTracker(
    val windowSecs: Long = 86400L,
    val requestLimit: Long = 20000L
) {
    data class Bucket(
        val maskedId: String,
        var requestsUsed: Long = 0L,
        var failedRequests: Long = 0L,
        var bytesTotal: Long = 0L,
        var nextResetAt: Long = 0L,
        var exhausted: Boolean = false,
        var quarantined: Boolean = false
    )

    private val buckets = mutableMapOf<String, Bucket>()
    private val lock = Any()

    fun register(id: String) {
        synchronized(lock) {
            buckets.getOrPut(id) {
                val masked = if (id.length <= 8) id else "${id.take(4)}...${id.takeLast(4)}"
                Bucket(maskedId = masked)
            }
        }
    }

    fun recordOutcome(id: String, nowUnix: Long, upBytes: Long, downBytes: Long, success: Boolean) {
        synchronized(lock) {
            val b = buckets.getOrPut(id) {
                val masked = if (id.length <= 8) id else "${id.take(4)}...${id.takeLast(4)}"
                Bucket(maskedId = masked)
            }

            if (b.nextResetAt > 0 && nowUnix >= b.nextResetAt) {
                b.requestsUsed = 0L
                b.failedRequests = 0L
                b.bytesTotal = 0L
                b.nextResetAt = 0L
                b.exhausted = false
                b.quarantined = false
            }

            if (b.nextResetAt == 0L) {
                b.nextResetAt = nowUnix + windowSecs
            }

            b.requestsUsed++
            b.bytesTotal += (upBytes + downBytes)

            if (!success) {
                b.failedRequests++
                if (b.failedRequests >= 5) {
                    b.quarantined = true
                }
            }

            if (b.requestsUsed >= requestLimit) {
                b.exhausted = true
            }
        }
    }

    fun selectBestAccount(nowUnix: Long): String? {
        synchronized(lock) {
            var bestId: String? = null
            var lowestUsage = Long.MAX_VALUE

            for ((id, b) in buckets) {
                if (b.nextResetAt > 0 && nowUnix >= b.nextResetAt) {
                    b.requestsUsed = 0L
                    b.failedRequests = 0L
                    b.bytesTotal = 0L
                    b.nextResetAt = 0L
                    b.exhausted = false
                    b.quarantined = false
                }

                if (b.exhausted || b.quarantined) continue

                if (b.requestsUsed < lowestUsage) {
                    lowestUsage = b.requestsUsed
                    bestId = id
                }
            }
            return bestId
        }
    }
}
