package com.luminet.android.tunnel

/**
 * DNS Poison Detector and Clean Resolver Vault for Android clients.
 * Originates from RedCloud Windows core and adapted for LumiNet unified network plane.
 */
object DnsPoisonDetector {

    data class PoisonCheckResult(
        val isPoisoned: Boolean,
        val reason: String? = null
    )

    data class VerifiedDnsRecord(
        val ip: String,
        val latencyMs: Long,
        val isClean: Boolean,
        val label: String,
        val consecutiveSuccesses: Int
    )

    /**
     * Inspects an IPv4 string and determines whether it represents a hostile censorship
     * redirection page (e.g. Iranian 10.10.34.0/24), private address, loopback, or invalid range.
     */
    fun isPoisonedIPv4(ipStr: String): PoisonCheckResult {
        val parts = ipStr.split(".")
        if (parts.size != 4) {
            return PoisonCheckResult(isPoisoned = true, reason = "Invalid IPv4 format")
        }

        val octets = IntArray(4)
        for (i in 0..3) {
            val v = parts[i].toIntOrNull() ?: return PoisonCheckResult(isPoisoned = true, reason = "Non-numeric octet")
            if (v !in 0..255) {
                return PoisonCheckResult(isPoisoned = true, reason = "Octet out of bounds")
            }
            octets[i] = v
        }

        // Iranian National Filtering redirect page: 10.10.34.0/24
        if (octets[0] == 10 && octets[1] == 10 && octets[2] == 34) {
            return PoisonCheckResult(isPoisoned = true, reason = "Iranian Censorship Redirect Page (10.10.34.0/24)")
        }

        // RFC 1918 Class A: 10.0.0.0/8
        if (octets[0] == 10) {
            return PoisonCheckResult(isPoisoned = true, reason = "Bogus Private RFC 1918 Class A (10.0.0.0/8)")
        }

        // Loopback: 127.0.0.0/8
        if (octets[0] == 127) {
            return PoisonCheckResult(isPoisoned = true, reason = "Bogus Loopback Address (127.0.0.0/8)")
        }

        // Zero / Unspecified: 0.0.0.0/8
        if (octets[0] == 0) {
            return PoisonCheckResult(isPoisoned = true, reason = "Bogus Unspecified Address (0.0.0.0/8)")
        }

        // RFC 1918 Class C: 192.168.0.0/16
        if (octets[0] == 192 && octets[1] == 168) {
            return PoisonCheckResult(isPoisoned = true, reason = "Bogus Private RFC 1918 Class C (192.168.0.0/16)")
        }

        // RFC 1918 Class B: 172.16.0.0 - 172.31.255.255
        if (octets[0] == 172 && octets[1] in 16..31) {
            return PoisonCheckResult(isPoisoned = true, reason = "Bogus Private RFC 1918 Class B (172.16.0.0/12)")
        }

        // CGNAT: 100.64.0.0/10
        if (octets[0] == 100 && octets[1] in 64..127) {
            return PoisonCheckResult(isPoisoned = true, reason = "Bogus CGNAT RFC 6598 (100.64.0.0/10)")
        }

        // Link-local: 169.254.0.0/16
        if (octets[0] == 169 && octets[1] == 254) {
            return PoisonCheckResult(isPoisoned = true, reason = "Bogus Link-Local RFC 3927 (169.254.0.0/16)")
        }

        // Benchmarking: 198.18.0.0/15
        if (octets[0] == 198 && (octets[1] == 18 || octets[1] == 19)) {
            return PoisonCheckResult(isPoisoned = true, reason = "Bogus Benchmarking RFC 2544 (198.18.0.0/15)")
        }

        // Broadcast: 255.255.255.255
        if (octets[0] == 255 && octets[1] == 255 && octets[2] == 255 && octets[3] == 255) {
            return PoisonCheckResult(isPoisoned = true, reason = "Bogus Broadcast Address (255.255.255.255)")
        }

        // Multicast: 224.0.0.0/4
        if (octets[0] in 224..239) {
            return PoisonCheckResult(isPoisoned = true, reason = "Bogus Multicast Address (224.0.0.0/4)")
        }

        return PoisonCheckResult(isPoisoned = false, reason = null)
    }

    /**
     * In-memory clean resolver vault.
     */
    class DnsVault {
        private val records = mutableMapOf<String, VerifiedDnsRecord>()

        @Synchronized
        fun updateRecord(ip: String, latencyMs: Long, isClean: Boolean, label: String = "") {
            val existing = records[ip]
            if (existing != null) {
                val succ = if (isClean) existing.consecutiveSuccesses + 1 else 0
                records[ip] = existing.copy(
                    latencyMs = latencyMs,
                    isClean = isClean,
                    consecutiveSuccesses = succ,
                    label = if (label.isNotEmpty()) label else existing.label
                )
            } else {
                records[ip] = VerifiedDnsRecord(
                    ip = ip,
                    latencyMs = latencyMs,
                    isClean = isClean,
                    label = label,
                    consecutiveSuccesses = if (isClean) 1 else 0
                )
            }
        }

        @Synchronized
        fun rankCleanResolvers(): List<VerifiedDnsRecord> {
            return records.values
                .filter { it.isClean && it.consecutiveSuccesses > 0 }
                .sortedBy { it.latencyMs }
        }

        @Synchronized
        fun getFastestClean(): VerifiedDnsRecord? {
            return rankCleanResolvers().firstOrNull()
        }
    }
}
