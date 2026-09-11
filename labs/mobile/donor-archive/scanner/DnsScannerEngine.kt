package com.luminet.android.scanner

import java.io.Reader
import java.io.StringReader
import java.security.SecureRandom
import kotlin.math.min

/**
 * Cleanroom implementation of IPv4 subnet calculations and target walking.
 */
data class Ipv4Prefix(
    val baseAddress: Long,
    val prefixLength: Int,
) {
    init {
        require(prefixLength in 0..32) { "prefixLength must be between 0 and 32" }
    }

    val maskedBaseAddress: Long = Ipv4Math.maskAddress(baseAddress, prefixLength)

    fun normalizedString(): String = "${Ipv4Math.formatAddress(maskedBaseAddress)}/$prefixLength"

    fun addressCount(): Long = 1L shl (32 - prefixLength)

    fun usableHostCount(): Long {
        val total = addressCount()
        return if (prefixLength < 31 && total >= 2) total - 2 else total
    }

    fun hostBounds(): LongRange? {
        val total = addressCount()
        if (total <= 0) return null

        val start = if (prefixLength < 31 && total >= 2) maskedBaseAddress + 1 else maskedBaseAddress
        val end = if (prefixLength < 31 && total >= 2) maskedBaseAddress + total - 2 else maskedBaseAddress + total - 1
        return start..end
    }
}

object Ipv4Math {
    fun parseTarget(raw: String): Ipv4Prefix {
        val trimmed = raw.trim()
        return if (trimmed.contains('/')) parsePrefix(trimmed) else Ipv4Prefix(parseAddress(trimmed), 32)
    }

    fun parsePrefix(raw: String): Ipv4Prefix {
        val parts = raw.split('/')
        require(parts.size == 2) { "invalid target \"$raw\"" }
        val address = parseAddress(parts[0].trim())
        val prefixLength = parts[1].trim().toIntOrNull()
            ?: throw IllegalArgumentException("invalid target \"$raw\"")
        require(prefixLength in 0..32) { "invalid target \"$raw\"" }
        return Ipv4Prefix(address, prefixLength)
    }

    fun parseAddress(raw: String): Long {
        val octets = raw.split('.')
        require(octets.size == 4) { "invalid target \"$raw\"" }

        var value = 0L
        for (octet in octets) {
            require(octet.isNotBlank()) { "invalid target \"$raw\"" }
            val parsed = octet.toIntOrNull() ?: throw IllegalArgumentException("invalid target \"$raw\"")
            require(parsed in 0..255) { "invalid target \"$raw\"" }
            value = (value shl 8) or parsed.toLong()
        }
        return value and 0xFFFF_FFFFL
    }

    fun formatAddress(raw: Long): String {
        return buildString {
            append((raw shr 24) and 0xFF)
            append('.')
            append((raw shr 16) and 0xFF)
            append('.')
            append((raw shr 8) and 0xFF)
            append('.')
            append(raw and 0xFF)
        }
    }

    fun maskAddress(raw: Long, prefixLength: Int): Long {
        if (prefixLength == 0) return 0L
        val shift = 32 - prefixLength
        val mask = ((0xFFFF_FFFFL shr shift) shl shift) and 0xFFFF_FFFFL
        return raw and mask
    }
}

class HostWalker {
    suspend fun walk(
        prefixes: List<String>,
        limit: Long = Long.MAX_VALUE,
        onHost: suspend (address: String, prefix: String) -> Boolean,
    ): Long {
        var emitted = 0L

        for (prefixStr in prefixes) {
            val prefix = try {
                Ipv4Math.parsePrefix(prefixStr)
            } catch (e: IllegalArgumentException) {
                continue
            }

            val bounds = prefix.hostBounds() ?: continue
            for (rawAddress in bounds) {
                if (emitted >= limit) return emitted
                if (!onHost(Ipv4Math.formatAddress(rawAddress), prefixStr)) return emitted
                emitted += 1
            }
        }
        return emitted
    }
}

object TargetInputNormalizer {
    const val DEFAULT_MAX_TARGETS = 100_000
    const val DEFAULT_MAX_CHARACTERS = 2_000_000

    data class NormalizedTargets(
        val text: String,
        val targetCount: Int,
    )

    fun normalizeImportedTargets(rawInput: String): String {
        return normalizeImportedTargets(
            reader = StringReader(rawInput),
            maxTargets = Int.MAX_VALUE,
            maxCharacters = Int.MAX_VALUE,
        ).text
    }

    fun normalizeImportedTargets(
        reader: Reader,
        maxTargets: Int = DEFAULT_MAX_TARGETS,
        maxCharacters: Int = DEFAULT_MAX_CHARACTERS,
    ): NormalizedTargets {
        val normalized = StringBuilder()
        val token = StringBuilder()
        val buffer = CharArray(8_192)
        var targetCount = 0

        fun flushToken() {
            val value = token.toString().trim()
            token.setLength(0)
            if (value.isEmpty()) return

            if (targetCount >= maxTargets) {
                throw IllegalArgumentException("Import file has more than $maxTargets targets.")
            }

            val separatorLength = if (normalized.isEmpty()) 0 else 1
            if (normalized.length + separatorLength + value.length > maxCharacters) {
                throw IllegalArgumentException("Import file exceeds character limit.")
            }

            if (normalized.isNotEmpty()) normalized.append('\n')
            normalized.append(value)
            targetCount++
        }

        while (true) {
            val read = reader.read(buffer)
            if (read < 0) break

            for (index in 0 until read) {
                when (val char = buffer[index]) {
                    '\uFEFF' -> Unit
                    ',', '\n', '\r' -> flushToken()
                    else -> {
                        token.append(char)
                        if (token.length > maxCharacters) {
                            throw IllegalArgumentException("Target token exceeds character limit.")
                        }
                    }
                }
            }
        }
        flushToken()

        return NormalizedTargets(
            text = normalized.toString(),
            targetCount = targetCount,
        )
    }
}

/**
 * DNS Tunnel and Transparent Proxy Detection Engine.
 */
class DnsScannerEngine {
    companion object {
        val RFC5737_TEST_NET_IPS = listOf("192.0.2.1", "198.51.100.1", "203.0.113.1")
        private const val BASE32_ALPHABET = "abcdefghijklmnopqrstuvwxyz234567"
        private val SECURE_RANDOM = SecureRandom()

        fun generateTunnelRealismQName(domain: String): String {
            val sb = StringBuilder(57)
            for (i in 0 until 57) {
                sb.append(BASE32_ALPHABET[SECURE_RANDOM.nextInt(BASE32_ALPHABET.length)])
            }
            val clean = domain.trimEnd('.')
            return "$sb.$clean."
        }

        fun generateNearbyIps(centerIp: String, offsets: List<Int> = listOf(-16, -8, -4, -2, -1, 1, 2, 4, 8, 16)): List<String> {
            val raw = try {
                Ipv4Math.parseAddress(centerIp)
            } catch (e: Exception) {
                return emptyList()
            }

            val octet0 = (raw shr 24) and 0xFF
            val octet1 = (raw shr 16) and 0xFF
            val octet2 = (raw shr 8) and 0xFF
            val hostOctet = (raw and 0xFF).toInt()

            val results = mutableListOf<String>()
            val seen = mutableSetOf<Int>()

            for (offset in offsets) {
                val targetHost = hostOctet + offset
                if (targetHost in 1..254 && targetHost != hostOctet && seen.add(targetHost)) {
                    val candidateRaw = (octet0 shl 24) or (octet1 shl 16) or (octet2 shl 8) or targetHost.toLong()
                    results.add(Ipv4Math.formatAddress(candidateRaw))
                }
            }
            return results
        }

        fun computeTunnelScore(
            nsOk: Boolean,
            txtOk: Boolean,
            randomSubOk: Boolean,
            realismOk: Boolean,
            edns0Supported: Boolean,
            nxdomainRatio: Double,
        ): Int {
            var score = 0
            if (nsOk) score++
            if (txtOk) score++
            if (randomSubOk) score++
            if (realismOk) score++
            if (edns0Supported) score++
            if (nxdomainRatio >= 0.75) score++
            return score
        }
    }
}
