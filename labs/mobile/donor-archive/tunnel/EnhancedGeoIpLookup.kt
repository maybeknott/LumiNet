package com.luminet.android.tunnel

data class AndroidGeoCidrEntry(
    val netAddr: Long,
    val mask: Long,
    val countryCode: String
)

class EnhancedGeoIpLookup {
    private val entries = mutableListOf<AndroidGeoCidrEntry>()

    fun addCidr(ipStr: String, maskBits: Int, countryCode: String) {
        val ipLong = parseIpv4ToLong(ipStr) ?: return
        val mask = if (maskBits == 0) 0L else (0xFFFFFFFFL shl (32 - maskBits)) and 0xFFFFFFFFL
        entries.add(
            AndroidGeoCidrEntry(
                netAddr = ipLong and mask,
                mask = mask,
                countryCode = countryCode.trim().uppercase()
            )
        )
    }

    fun lookup(ipStr: String): String? {
        val ipLong = parseIpv4ToLong(ipStr) ?: return null
        var bestMatch: String? = null
        var bestMask = -1L

        for (e in entries) {
            if ((ipLong and e.mask) == e.netAddr) {
                if (e.mask > bestMask) {
                    bestMatch = e.countryCode
                    bestMask = e.mask
                }
            }
        }
        return bestMatch
    }

    companion object {
        fun isPrivate(ipStr: String): Boolean {
            val parts = ipStr.split(".")
            if (parts.size != 4) return false
            val first = parts[0].toIntOrNull() ?: return false
            val second = parts[1].toIntOrNull() ?: return false

            return when (first) {
                10, 127 -> true
                172 -> second in 16..31
                192 -> second == 168
                else -> false
            }
        }

        private fun parseIpv4ToLong(ip: String): Long? {
            val parts = ip.split(".")
            if (parts.size != 4) return null
            var res = 0L
            for (p in parts) {
                val octet = p.toLongOrNull() ?: return null
                if (octet !in 0..255) return null
                res = (res shl 8) or octet
            }
            return res
        }
    }
}
