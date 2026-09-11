package com.luminet.android.tunnel

import java.nio.ByteBuffer
import java.nio.ByteOrder
import java.security.MessageDigest
import java.security.SecureRandom
import java.util.Arrays

/**
 * Tactical Tunnel Session Obfuscator, Preamble Framing & Dynamic Tactics Engine.
 * Conforms to strict architectural isolation rules: zero vendor prefixes.
 */
class TacticalTunnelSession {
    companion object {
        const val OBFUSCATE_SEED_LENGTH = 16
        const val OBFUSCATE_KEY_LENGTH = 16
        const val OBFUSCATE_HASH_ITERATIONS = 6000
        const val OBFUSCATE_MAX_PADDING = 8192
        const val OBFUSCATE_MAGIC_VALUE = 0x0BF5CA7E
        val OBFUSCATE_CLIENT_TO_SERVER_IV = "client_to_server".toByteArray(Charsets.UTF_8)
        val OBFUSCATE_SERVER_TO_CLIENT_IV = "server_to_client".toByteArray(Charsets.UTF_8)
        const val PREAMBLE_HEADER_LENGTH = OBFUSCATE_SEED_LENGTH + 8 // 16B seed + 4B magic + 4B padding len

        /**
         * Derives a 16-byte key using 6000 recursive rounds of SHA-1 over seed, keyword, and IV.
         */
        fun deriveKey(seed: ByteArray, keyword: ByteArray, iv: ByteArray): ByteArray {
            require(seed.size == OBFUSCATE_SEED_LENGTH) { "Seed must be 16 bytes" }
            val md = MessageDigest.getInstance("SHA-1")
            md.update(seed)
            md.update(keyword)
            md.update(iv)
            var digest = md.digest()

            for (i in 0 until OBFUSCATE_HASH_ITERATIONS) {
                md.reset()
                md.update(digest)
                digest = md.digest()
            }

            return digest.copyOfRange(0, OBFUSCATE_KEY_LENGTH)
        }
    }

    /**
     * Standard RC4 stream cipher state for stream obfuscation.
     */
    class StreamCipher(key: ByteArray) {
        private val s = IntArray(256) { it }
        private var i = 0
        private var j = 0

        init {
            var jj = 0
            val keyLen = if (key.isEmpty()) 1 else key.size
            for (ii in 0 until 256) {
                val keyByte = if (key.isEmpty()) 0 else (key[ii % keyLen].toInt() and 0xFF)
                jj = (jj + s[ii] + keyByte) and 0xFF
                val tmp = s[ii]
                s[ii] = s[jj]
                s[jj] = tmp
            }
        }

        fun applyKeyStream(buf: ByteArray, offset: Int = 0, length: Int = buf.size) {
            for (idx in offset until (offset + length)) {
                i = (i + 1) and 0xFF
                j = (j + s[i]) and 0xFF
                val tmp = s[i]
                s[i] = s[j]
                s[j] = tmp
                val k = s[(s[i] + s[j]) and 0xFF]
                buf[idx] = (buf[idx].toInt() xor k).toByte()
            }
        }
    }

    /**
     * Bidirectional session obfuscator instance.
     */
    class SessionObfuscator(
        val keyword: ByteArray,
        val seed: ByteArray,
        val paddingLen: Int,
        private val clientToServerCipher: StreamCipher,
        private val serverToClientCipher: StreamCipher
    ) {
        companion object {
            fun createClient(keyword: ByteArray, seed: ByteArray, paddingLen: Int): SessionObfuscator {
                require(seed.size == OBFUSCATE_SEED_LENGTH) { "Seed must be 16 bytes" }
                require(paddingLen <= OBFUSCATE_MAX_PADDING) { "Padding exceeds maximum" }

                val c2sKey = deriveKey(seed, keyword, OBFUSCATE_CLIENT_TO_SERVER_IV)
                val s2cKey = deriveKey(seed, keyword, OBFUSCATE_SERVER_TO_CLIENT_IV)

                return SessionObfuscator(
                    keyword = keyword.clone(),
                    seed = seed.clone(),
                    paddingLen = paddingLen,
                    clientToServerCipher = StreamCipher(c2sKey),
                    serverToClientCipher = StreamCipher(s2cKey)
                )
            }

            fun createServerFromPreamble(keyword: ByteArray, preamble: ByteArray): Pair<SessionObfuscator, ByteArray> {
                if (preamble.size < PREAMBLE_HEADER_LENGTH) {
                    throw IllegalArgumentException("Preamble too short for header")
                }

                val seed = preamble.copyOfRange(0, OBFUSCATE_SEED_LENGTH)
                val c2sKey = deriveKey(seed, keyword, OBFUSCATE_CLIENT_TO_SERVER_IV)
                val s2cKey = deriveKey(seed, keyword, OBFUSCATE_SERVER_TO_CLIENT_IV)

                val c2sCipher = StreamCipher(c2sKey)
                val s2cCipher = StreamCipher(s2cKey)

                val encHeader = preamble.copyOfRange(OBFUSCATE_SEED_LENGTH, PREAMBLE_HEADER_LENGTH)
                c2sCipher.applyKeyStream(encHeader)

                val bb = ByteBuffer.wrap(encHeader).order(ByteOrder.BIG_ENDIAN)
                val magic = bb.int
                if (magic != OBFUSCATE_MAGIC_VALUE) {
                    throw IllegalStateException("Invalid magic preamble header: 0x" + Integer.toHexString(magic))
                }

                val paddingLen = bb.int
                if (paddingLen > OBFUSCATE_MAX_PADDING) {
                    throw IllegalArgumentException("Padding exceeds maximum")
                }

                val totalReq = PREAMBLE_HEADER_LENGTH + paddingLen
                if (preamble.size < totalReq) {
                    throw IllegalArgumentException("Preamble too short for declared padding")
                }

                val padding = preamble.copyOfRange(PREAMBLE_HEADER_LENGTH, totalReq)
                c2sCipher.applyKeyStream(padding)

                val session = SessionObfuscator(
                    keyword = keyword.clone(),
                    seed = seed,
                    paddingLen = paddingLen,
                    clientToServerCipher = c2sCipher,
                    serverToClientCipher = s2cCipher
                )

                return Pair(session, padding)
            }
        }

        fun generateClientPreamble(paddingBytes: ByteArray): ByteArray {
            require(paddingBytes.size == paddingLen) { "Padding buffer size mismatch" }

            val payload = ByteBuffer.allocate(8 + paddingLen).order(ByteOrder.BIG_ENDIAN)
            payload.putInt(OBFUSCATE_MAGIC_VALUE)
            payload.putInt(paddingLen)
            payload.put(paddingBytes)

            val payloadBytes = payload.array()
            clientToServerCipher.applyKeyStream(payloadBytes)

            val preamble = ByteArray(OBFUSCATE_SEED_LENGTH + payloadBytes.size)
            System.arraycopy(seed, 0, preamble, 0, OBFUSCATE_SEED_LENGTH)
            System.arraycopy(payloadBytes, 0, preamble, OBFUSCATE_SEED_LENGTH, payloadBytes.size)
            return preamble
        }

        fun obfuscateClientToServer(buf: ByteArray, offset: Int = 0, length: Int = buf.size) {
            clientToServerCipher.applyKeyStream(buf, offset, length)
        }

        fun obfuscateServerToClient(buf: ByteArray, offset: Int = 0, length: Int = buf.size) {
            serverToClientCipher.applyKeyStream(buf, offset, length)
        }
    }

    /**
     * Tactical configuration profile for dynamic network routing.
     */
    data class TacticalProfile(
        val ttlMs: Long,
        val parameters: Map<String, String>,
        val tag: String = computeTag(parameters)
    ) {
        companion object {
            fun computeTag(parameters: Map<String, String>): String {
                val sortedKeys = parameters.keys.sorted()
                val md = MessageDigest.getInstance("SHA-1")
                for (k in sortedKeys) {
                    md.update(k.toByteArray(Charsets.UTF_8))
                    md.update("=".toByteArray(Charsets.UTF_8))
                    md.update((parameters[k] ?: "").toByteArray(Charsets.UTF_8))
                    md.update(";".toByteArray(Charsets.UTF_8))
                }
                return md.digest().joinToString("") { "%02x".format(it) }
            }
        }
    }

    /**
     * Tactical filter criteria.
     */
    data class TacticalFilter(
        val regions: List<String>,
        val asns: List<Long>,
        val maxLatencyMs: Long?,
        val profile: TacticalProfile
    ) {
        fun matches(region: String, asn: Long, latencyMs: Long): Boolean {
            if (regions.isNotEmpty() && regions.none { it.equals(region, ignoreCase = true) }) {
                return false
            }
            if (asns.isNotEmpty() && !asns.contains(asn)) {
                return false
            }
            if (maxLatencyMs != null && latencyMs > maxLatencyMs) {
                return false
            }
            return true
        }
    }

    /**
     * Tactical engine resolving optimal profile per network attributes.
     */
    class TacticalEngine(val defaultProfile: TacticalProfile) {
        private val filters = mutableListOf<TacticalFilter>()
        private var cachedProfile: TacticalProfile? = null
        private var cachedAtMs: Long = 0L

        fun addFilter(filter: TacticalFilter) {
            filters.add(filter)
        }

        @Synchronized
        fun resolveProfile(region: String, asn: Long, latencyMs: Long, forceRefresh: Boolean = false): TacticalProfile {
            val now = System.currentTimeMillis()
            if (!forceRefresh && cachedProfile != null) {
                if ((now - cachedAtMs) < (cachedProfile?.ttlMs ?: 0L)) {
                    return cachedProfile!!
                }
            }

            val merged = HashMap<String, String>(defaultProfile.parameters)
            var appliedTtl = defaultProfile.ttlMs

            for (f in filters) {
                if (f.matches(region, asn, latencyMs)) {
                    merged.putAll(f.profile.parameters)
                    appliedTtl = f.profile.ttlMs
                }
            }

            val resolved = TacticalProfile(appliedTtl, merged)
            cachedProfile = resolved
            cachedAtMs = now
            return resolved
        }
    }
}
