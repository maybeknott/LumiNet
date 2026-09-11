package com.luminet.android.tunnel

import java.net.InetAddress

object AdblockHostsParser {

    private val DOMAIN_REGEX = Regex("^(?:[a-z0-9](?:[a-z0-9\\-]{0,61}[a-z0-9])?\\.)+[a-z]{2,}$")
    private val WILDCARD_REGEX = Regex("[*?]")

    private val HOSTS_PREFIXES = setOf("0.0.0.0", "127.0.0.1", "::1", "::0")
    private val SKIP_NAMES = setOf(
        "localhost",
        "local",
        "broadcasthost",
        "localhost.localdomain",
        "ip6-localhost",
        "ip6-loopback"
    )

    fun parseHostsText(text: String): List<String> {
        val seen = mutableSetOf<String>()
        val domains = mutableListOf<String>()

        for (rawLine in text.lineSequence()) {
            var line = rawLine.trim()
            if (line.isEmpty() || line.startsWith("#")) continue

            val commentPos = line.indexOf(" #")
            if (commentPos != -1) {
                line = line.substring(0, commentPos).trim()
            }

            val parts = line.split(Regex("\\s+")).filter { it.isNotEmpty() }
            val domain = when (parts.size) {
                2 -> if (HOSTS_PREFIXES.contains(parts[0])) parts[1].lowercase().trimEnd('.') else continue
                1 -> parts[0].lowercase().trimEnd('.')
                else -> continue
            }

            if (WILDCARD_REGEX.containsMatchIn(domain)) continue
            if (SKIP_NAMES.contains(domain)) continue

            // Skip IP addresses
            try {
                if (domain.matches(Regex("^(?:\\d{1,3}\\.){3}\\d{1,3}$")) || domain.contains(":")) {
                    continue
                }
            } catch (_: Exception) {}

            if (!DOMAIN_REGEX.matches(domain)) continue

            if (seen.add(domain)) {
                domains.add(domain)
            }
        }

        return domains
    }
}
