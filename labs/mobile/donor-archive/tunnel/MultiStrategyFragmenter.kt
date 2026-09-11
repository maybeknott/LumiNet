package com.luminet.android.tunnel

import java.nio.charset.StandardCharsets

/**
 * Multi-Strategy TLS Fragmenter & Carrier Edge Selector.
 */
enum class MultiFragmentStrategy {
    FINALMASK_TLS_HELLO,
    FULL5,
    FULL10,
    FULL20,
    SNI_BOUNDARY,
    SNI_SPLIT,
    TLS_RECORD_FRAG,
    TLS_SNI_RECORDS,
    HALF,
    RAW,
}

data class FinalMaskSettings(
    val packet: String = "tlshello",
    val length: Int = 5,
    val delayMs: Int = 0,
    val maxSplit: Int = 2,
)

data class FinalMaskRewrite(
    val firstWrite: ByteArray,
    val trailingWrite: ByteArray? = null,
) {
    fun writes(): List<ByteArray> = listOfNotNull(firstWrite, trailingWrite)
    fun bytes(): ByteArray = firstWrite + (trailingWrite ?: byteArrayOf())

    override fun equals(other: Any?): Boolean {
        if (this === other) return true
        if (javaClass != other?.javaClass) return false
        other as FinalMaskRewrite
        if (!firstWrite.contentEquals(other.firstWrite)) return false
        if (trailingWrite != null) {
            if (other.trailingWrite == null) return false
            if (!trailingWrite.contentEquals(other.trailingWrite)) return false
        } else if (other.trailingWrite != null) return false
        return true
    }

    override fun hashCode(): Int {
        var result = firstWrite.contentHashCode()
        result = 31 * result + (trailingWrite?.contentHashCode() ?: 0)
        return result
    }
}

data class CarrierEdge(
    val address: String,
    val port: Int,
    val role: String,
    val finalmaskMaxSplit: Int = 2,
)

class CarrierRouteSelector(
    private val cooldownMs: Long = 12_000L,
    private val clockMs: () -> Long = System::currentTimeMillis,
) {
    private val failedUntil = mutableMapOf<String, Long>()

    @Synchronized
    fun orderedEdges(edges: List<CarrierEdge>): List<CarrierEdge> {
        val now = clockMs()
        val (healthy, coolingDown) = edges.partition {
            (failedUntil[it.address] ?: 0L) <= now
        }
        return healthy + coolingDown
    }

    @Synchronized
    fun recordFailure(edge: CarrierEdge) {
        failedUntil[edge.address] = clockMs() + cooldownMs
    }

    @Synchronized
    fun recordSuccess(edge: CarrierEdge) {
        failedUntil.remove(edge.address)
    }

    @Synchronized
    fun isInCooldown(edge: CarrierEdge): Boolean {
        return (failedUntil[edge.address] ?: 0L) > clockMs()
    }
}

object MultiStrategyFragmenter {
    fun locateSni(data: ByteArray): Pair<Int, Int>? {
        try {
            if (data.size < 9 || data[0].toInt() and 0xff != 0x16) return null
            val recordEnd = minOf(data.size, 5 + unsignedShort(data, 3))
            var position = 5
            if (unsigned(data[position]) != 0x01) return null
            position += 4 + 2 + 32
            val sessionLength = unsigned(data[position])
            position += 1 + sessionLength
            val cipherLength = unsignedShort(data, position)
            position += 2 + cipherLength
            val compressionLength = unsigned(data[position])
            position += 1 + compressionLength
            val extensionsLength = unsignedShort(data, position)
            position += 2
            val extensionsEnd = minOf(recordEnd, position + extensionsLength)
            while (position + 4 <= extensionsEnd) {
                val type = unsignedShort(data, position)
                val length = unsignedShort(data, position + 2)
                position += 4
                if (type == 0 && position + length <= extensionsEnd) {
                    var namePosition = position + 2
                    val namesEnd = position + length
                    while (namePosition + 3 <= namesEnd) {
                        val nameType = unsigned(data[namePosition])
                        val nameLength = unsignedShort(data, namePosition + 1)
                        namePosition += 3
                        if (nameType == 0 && namePosition + nameLength <= namesEnd) {
                            return namePosition to nameLength
                        }
                        namePosition += nameLength
                    }
                }
                position += length
            }
        } catch (_: Exception) {
            return null
        }
        return null
    }

    fun extractSni(data: ByteArray): String? {
        val loc = locateSni(data) ?: return null
        return String(data, loc.first, loc.second, StandardCharsets.US_ASCII)
    }

    fun rewriteFinalMaskWrites(
        data: ByteArray,
        settings: FinalMaskSettings = FinalMaskSettings(),
    ): FinalMaskRewrite {
        if (
            settings.packet != "tlshello" ||
            settings.length <= 0 ||
            settings.maxSplit < 2 ||
            data.size < 6 ||
            data[0].toInt() and 0xff != 0x16
        ) {
            return FinalMaskRewrite(data.copyOf())
        }
        val recordLength = unsignedShort(data, 3)
        val recordEnd = 5 + recordLength
        if (recordLength <= settings.length || recordEnd > data.size) {
            return FinalMaskRewrite(data.copyOf())
        }

        val version = data.copyOfRange(1, 3)
        val payload = data.copyOfRange(5, recordEnd)
        val first = tlsRecord(version, payload.copyOfRange(0, settings.length))
        val second = tlsRecord(version, payload.copyOfRange(settings.length, payload.size))
        val trailing = if (recordEnd < data.size) data.copyOfRange(recordEnd, data.size) else null
        return FinalMaskRewrite(first + second, trailing)
    }

    fun rewriteFinalMaskTlsHello(
        data: ByteArray,
        settings: FinalMaskSettings = FinalMaskSettings(),
    ): ByteArray = rewriteFinalMaskWrites(data, settings).bytes()

    fun fragment(
        data: ByteArray,
        strategy: MultiFragmentStrategy,
        settings: FinalMaskSettings = FinalMaskSettings(),
    ): List<ByteArray> = when (strategy) {
        MultiFragmentStrategy.FINALMASK_TLS_HELLO -> rewriteFinalMaskWrites(data, settings).writes()
        MultiFragmentStrategy.FULL5 -> fixedChunks(data, 5)
        MultiFragmentStrategy.FULL10 -> fixedChunks(data, 10)
        MultiFragmentStrategy.FULL20 -> fixedChunks(data, 20)
        MultiFragmentStrategy.SNI_BOUNDARY -> splitAtSni(data, atBoundary = true)
        MultiFragmentStrategy.SNI_SPLIT -> splitAtSni(data, atBoundary = false)
        MultiFragmentStrategy.TLS_RECORD_FRAG -> splitTlsRecord(data, atSni = false)
        MultiFragmentStrategy.TLS_SNI_RECORDS -> splitTlsRecord(data, atSni = true)
        MultiFragmentStrategy.HALF -> splitAt(data, data.size / 2)
        MultiFragmentStrategy.RAW -> listOf(data.copyOf())
    }

    private fun fixedChunks(data: ByteArray, size: Int): List<ByteArray> {
        if (data.isEmpty()) return listOf(data.copyOf())
        val safeSize = maxOf(1, size)
        return (data.indices step safeSize).map { offset ->
            data.copyOfRange(offset, minOf(offset + safeSize, data.size))
        }
    }

    private fun splitAtSni(data: ByteArray, atBoundary: Boolean): List<ByteArray> {
        val location = locateSni(data) ?: return splitAt(data, data.size / 2)
        val split = if (atBoundary) location.first else location.first + maxOf(1, location.second / 2)
        return splitAt(data, split)
    }

    private fun splitAt(data: ByteArray, requested: Int): List<ByteArray> {
        if (data.size < 2) return listOf(data.copyOf())
        val split = requested.coerceIn(1, data.size - 1)
        return listOf(data.copyOfRange(0, split), data.copyOfRange(split, data.size))
    }

    private fun splitTlsRecord(data: ByteArray, atSni: Boolean): List<ByteArray> {
        if (data.size < 6 || unsigned(data[0]) != 0x16) return listOf(data.copyOf())
        val payload = data.copyOfRange(5, data.size)
        if (payload.size < 2) return listOf(data.copyOf())
        val location = if (atSni) locateSni(data) else null
        val requested = if (location != null) location.first - 5 else payload.size / 2
        val split = requested.coerceIn(1, payload.size - 1)
        val version = data.copyOfRange(1, 3)
        return listOf(
            tlsRecord(version, payload.copyOfRange(0, split)),
            tlsRecord(version, payload.copyOfRange(split, payload.size)),
        )
    }

    private fun tlsRecord(version: ByteArray, payload: ByteArray): ByteArray = byteArrayOf(
        0x16,
        version[0],
        version[1],
        ((payload.size ushr 8) and 0xff).toByte(),
        (payload.size and 0xff).toByte(),
    ) + payload

    private fun unsigned(value: Byte) = value.toInt() and 0xff

    private fun unsignedShort(data: ByteArray, offset: Int): Int =
        (unsigned(data[offset]) shl 8) or unsigned(data[offset + 1])
}
