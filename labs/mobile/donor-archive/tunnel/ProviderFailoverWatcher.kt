package com.luminet.android.tunnel

enum class AndroidProviderStatus {
    OPERATIONAL, UNSTABLE, FAILED
}

data class AndroidProviderHealth(
    val providerName: String,
    var consecutiveFailures: Int = 0,
    var successfulHeartbeats: Long = 0,
    var lastLatencyMs: Long = 0,
    var status: AndroidProviderStatus = AndroidProviderStatus.OPERATIONAL
)

class ProviderFailoverWatcher(private val failoverThreshold: Int = 3) {
    private val providers = mutableMapOf<String, AndroidProviderHealth>()
    var activeProvider: String? = null
        private set

    fun registerProvider(name: String, isActive: Boolean) {
        providers[name] = AndroidProviderHealth(providerName = name)
        if (isActive) {
            activeProvider = name
        }
    }

    fun recordHeartbeat(name: String, latencyMs: Long, success: Boolean): String? {
        val p = providers[name] ?: return null
        var needsFailover = false

        if (success) {
            p.consecutiveFailures = 0
            p.successfulHeartbeats++
            p.lastLatencyMs = latencyMs
            p.status = AndroidProviderStatus.OPERATIONAL
        } else {
            p.consecutiveFailures++
            if (p.consecutiveFailures >= failoverThreshold) {
                p.status = AndroidProviderStatus.FAILED
                needsFailover = true
            } else {
                p.status = AndroidProviderStatus.UNSTABLE
            }
        }

        return if (needsFailover && activeProvider == name) {
            failoverToNext()
        } else {
            null
        }
    }

    fun failoverToNext(): String? {
        val candidate = providers.values
            .firstOrNull { it.status == AndroidProviderStatus.OPERATIONAL && it.providerName != activeProvider }
            ?.providerName

        if (candidate != null) {
            activeProvider = candidate
        }
        return candidate
    }

    fun getHealth(name: String): AndroidProviderHealth? = providers[name]
}
