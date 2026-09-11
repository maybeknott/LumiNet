package com.luminet.android.tunnel

import org.json.JSONArray
import org.json.JSONObject

enum class SplitTunnelMode(val label: String) {
    ALL("All apps"),
    ONLY("Only these apps"),
    EXCEPT("All except these")
}

data class SplitTunnelPolicy(
    val mode: SplitTunnelMode = SplitTunnelMode.ALL,
    val packages: Set<String> = emptySet()
) {
    fun effectivePackages(self: String): Set<String> = packages - self

    fun isEffectivelyEverything(self: String): Boolean = when (mode) {
        SplitTunnelMode.ALL -> true
        SplitTunnelMode.ONLY -> false
        SplitTunnelMode.EXCEPT -> effectivePackages(self).isEmpty()
    }

    fun validationError(self: String): String? = when {
        mode == SplitTunnelMode.ONLY && effectivePackages(self).isEmpty() ->
            "Choose at least one app, or switch back to All apps"
        else -> null
    }

    fun encode(): String = JSONObject()
        .put("mode", mode.name)
        .put("packages", JSONArray().apply { packages.sorted().forEach { put(it) } })
        .toString()

    companion object {
        fun decode(raw: String?): SplitTunnelPolicy {
            if (raw.isNullOrBlank()) return SplitTunnelPolicy()
            return runCatching {
                val json = JSONObject(raw)
                val list = json.optJSONArray("packages")
                SplitTunnelPolicy(
                    mode = SplitTunnelMode.entries
                        .firstOrNull { it.name == json.optString("mode") }
                        ?: SplitTunnelMode.ALL,
                    packages = buildSet {
                        for (index in 0 until (list?.length() ?: 0)) {
                            list?.optString(index)?.takeIf { it.isNotBlank() }?.let(::add)
                        }
                    }
                )
            }.getOrDefault(SplitTunnelPolicy())
        }
    }
}

/**
 * Exponential moving average rate calculation for traffic meters.
 */
class TrafficRateSmoother {
    private var smoothedDown = 0.0
    private var smoothedUp = 0.0

    fun smooth(rawDown: Long, rawUp: Long): Pair<Long, Long> {
        smoothedDown = if (smoothedDown <= 0.0) rawDown.toDouble() else smoothedDown * 0.4 + rawDown * 0.6
        smoothedUp = if (smoothedUp <= 0.0) rawUp.toDouble() else smoothedUp * 0.4 + rawUp * 0.6
        return Pair(smoothedDown.toLong(), smoothedUp.toLong())
    }

    fun reset() {
        smoothedDown = 0.0
        smoothedUp = 0.0
    }

    companion object {
        fun formatBytes(bytes: Long): String {
            if (bytes < 1024) return "$bytes B"
            val units = listOf("KB", "MB", "GB", "TB")
            var value = bytes.toDouble() / 1024
            var unit = 0
            while (value >= 1024 && unit < units.lastIndex) {
                value /= 1024
                unit++
            }
            return if (value < 10) "%.1f %s".format(value, units[unit])
            else "%.0f %s".format(value, units[unit])
        }

        fun formatRate(bytesPerSecond: Long): String = "${formatBytes(bytesPerSecond)}/s"
    }
}
