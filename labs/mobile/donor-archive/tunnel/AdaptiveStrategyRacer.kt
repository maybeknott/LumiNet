package com.luminet.android.tunnel

import java.nio.charset.StandardCharsets

/**
 * Granular fragmentation strategies including byte-per-character SNI splitting.
 */
enum class ExtendedFragmentStrategy(val rawName: String) {
    SNI_CHARS("sni_chars"),
    MULTI64("multi64"),
    FULL5("full5"),
    FULL10("full10"),
    FULL20("full20"),
    SNI_BOUNDARY("sni_boundary"),
    SNI_SPLIT("sni_split"),
    TLS_RECORD_FRAG("tls_record_frag"),
    TLS_SNI_RECORDS("tls_sni_records"),
    HALF("half"),
    RAW("raw"),
}

enum class StrategyResponseStatus {
    VALID,
    EMPTY_RESPONSE,
    ALERT_REJECTED,
    TRUNCATED_MALFORMED,
}

data class StrategyPlanEntry(
    val strategy: ExtendedFragmentStrategy,
    val delayMs: Int,
)

enum class CarrierMode {
    MCI,
    IRANCELL,
    ADAPTIVE,
}

class AdaptiveStrategyRacer(
    private val carrierMode: CarrierMode = CarrierMode.ADAPTIVE,
    private val fakeSni: String = "www.speedtest.net",
    private val fakeProbeEnabled: Boolean = true,
) {
    private val preferredStrategies = mutableMapOf<String, ExtendedFragmentStrategy>()

    @Synchronized
    fun planStrategies(host: String): List<StrategyPlanEntry> {
        val base = when (carrierMode) {
            CarrierMode.MCI -> listOf(
                StrategyPlanEntry(ExtendedFragmentStrategy.FULL20, 1),
                StrategyPlanEntry(ExtendedFragmentStrategy.FULL10, 2),
                StrategyPlanEntry(ExtendedFragmentStrategy.FULL5, 5),
                StrategyPlanEntry(ExtendedFragmentStrategy.SNI_CHARS, 2),
                StrategyPlanEntry(ExtendedFragmentStrategy.SNI_BOUNDARY, 1),
                StrategyPlanEntry(ExtendedFragmentStrategy.SNI_SPLIT, 3),
                StrategyPlanEntry(ExtendedFragmentStrategy.TLS_RECORD_FRAG, 3),
                StrategyPlanEntry(ExtendedFragmentStrategy.TLS_SNI_RECORDS, 3),
                StrategyPlanEntry(ExtendedFragmentStrategy.HALF, 3),
                StrategyPlanEntry(ExtendedFragmentStrategy.RAW, 0),
            )
            CarrierMode.IRANCELL -> listOf(
                StrategyPlanEntry(ExtendedFragmentStrategy.MULTI64, 0),
                StrategyPlanEntry(ExtendedFragmentStrategy.SNI_BOUNDARY, 0),
                StrategyPlanEntry(ExtendedFragmentStrategy.TLS_RECORD_FRAG, 1),
                StrategyPlanEntry(ExtendedFragmentStrategy.SNI_CHARS, 1),
                StrategyPlanEntry(ExtendedFragmentStrategy.SNI_SPLIT, 2),
                StrategyPlanEntry(ExtendedFragmentStrategy.HALF, 2),
                StrategyPlanEntry(ExtendedFragmentStrategy.RAW, 0),
            )
            CarrierMode.ADAPTIVE -> listOf(
                StrategyPlanEntry(ExtendedFragmentStrategy.SNI_SPLIT, 2),
                StrategyPlanEntry(ExtendedFragmentStrategy.SNI_BOUNDARY, 1),
                StrategyPlanEntry(ExtendedFragmentStrategy.SNI_CHARS, 1),
                StrategyPlanEntry(ExtendedFragmentStrategy.TLS_SNI_RECORDS, 2),
                StrategyPlanEntry(ExtendedFragmentStrategy.TLS_RECORD_FRAG, 2),
                StrategyPlanEntry(ExtendedFragmentStrategy.MULTI64, 0),
                StrategyPlanEntry(ExtendedFragmentStrategy.HALF, 2),
                StrategyPlanEntry(ExtendedFragmentStrategy.RAW, 0),
            )
        }

        val preferred = preferredStrategies[host] ?: return base
        val (first, rest) = base.partition { it.strategy == preferred }
        return first + rest
    }

    @Synchronized
    fun recordSuccess(host: String, strategy: ExtendedFragmentStrategy) {
        preferredStrategies[host] = strategy
    }

    @Synchronized
    fun preferredStrategy(host: String): ExtendedFragmentStrategy? {
        return preferredStrategies[host]
    }

    fun buildFakeProbe(): ByteArray? {
        if (!fakeProbeEnabled || fakeSni.isEmpty()) return null
        return buildDisposableFakeProbe(fakeSni)
    }

    companion object {
        fun validateStrategyResponse(response: ByteArray?): StrategyResponseStatus {
            if (response == null || response.isEmpty()) return StrategyResponseStatus.EMPTY_RESPONSE
            val first = response[0].toInt() and 0xff
            if (first == 0x15) return StrategyResponseStatus.ALERT_REJECTED
            if (response.size < 8 && (first == 0x14 || first == 0x16 || first == 0x17)) {
                return StrategyResponseStatus.TRUNCATED_MALFORMED
            }
            return StrategyResponseStatus.VALID
        }

        fun fragmentExtended(
            data: ByteArray,
            strategy: ExtendedFragmentStrategy,
            chunkSize: Int = 64,
        ): List<ByteArray> {
            if (data.size < 2) return listOf(data.copyOf())
            val location = MultiStrategyFragmenter.locateSni(data)

            return when (strategy) {
                ExtendedFragmentStrategy.RAW -> listOf(data.copyOf())
                ExtendedFragmentStrategy.HALF -> {
                    val cut = maxOf(1, data.size / 2)
                    listOf(data.copyOfRange(0, cut), data.copyOfRange(cut, data.size))
                }
                ExtendedFragmentStrategy.FULL5 -> fixedChunks(data, 5)
                ExtendedFragmentStrategy.FULL10 -> fixedChunks(data, 10)
                ExtendedFragmentStrategy.FULL20 -> fixedChunks(data, 20)
                ExtendedFragmentStrategy.MULTI64 -> fixedChunks(data, if (chunkSize > 0) chunkSize else 64)
                ExtendedFragmentStrategy.SNI_BOUNDARY -> {
                    val cut = if (location != null) location.first.coerceIn(1, data.size - 1) else data.size / 2
                    listOf(data.copyOfRange(0, cut), data.copyOfRange(cut, data.size))
                }
                ExtendedFragmentStrategy.SNI_SPLIT -> {
                    val cut = if (location != null) {
                        (location.first + maxOf(1, location.second / 2)).coerceIn(1, data.size - 1)
                    } else {
                        data.size / 2
                    }
                    listOf(data.copyOfRange(0, cut), data.copyOfRange(cut, data.size))
                }
                ExtendedFragmentStrategy.SNI_CHARS -> {
                    if (location != null) {
                        val out = mutableListOf<ByteArray>()
                        if (location.first > 0) {
                            out.add(data.copyOfRange(0, location.first))
                        }
                        for (i in 0 until location.second) {
                            out.add(byteArrayOf(data[location.first + i]))
                        }
                        if (location.first + location.second < data.size) {
                            out.add(data.copyOfRange(location.first + location.second, data.size))
                        }
                        out
                    } else {
                        val cut = maxOf(1, data.size / 2)
                        listOf(data.copyOfRange(0, cut), data.copyOfRange(cut, data.size))
                    }
                }
                ExtendedFragmentStrategy.TLS_RECORD_FRAG -> {
                    splitTlsRecord(data, atSni = false, location = location)
                }
                ExtendedFragmentStrategy.TLS_SNI_RECORDS -> {
                    splitTlsRecord(data, atSni = true, location = location)
                }
            }
        }

        private fun fixedChunks(data: ByteArray, size: Int): List<ByteArray> {
            val safeSize = maxOf(1, size)
            return (data.indices step safeSize).map { offset ->
                data.copyOfRange(offset, minOf(offset + safeSize, data.size))
            }
        }

        private fun splitTlsRecord(data: ByteArray, atSni: Boolean, location: Pair<Int, Int>?): List<ByteArray> {
            if (data.size < 6 || (data[0].toInt() and 0xff) != 0x16) return listOf(data.copyOf())
            val payload = data.copyOfRange(5, data.size)
            if (payload.size < 2) return listOf(data.copyOf())
            val split = if (atSni && location != null) {
                (location.first - 5).coerceIn(1, payload.size - 1)
            } else {
                maxOf(1, payload.size / 2)
            }
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

        fun buildDisposableFakeProbe(fakeSni: String): ByteArray {
            val hostBytes = fakeSni.toByteArray(StandardCharsets.US_ASCII)
            val pkt = mutableListOf<Byte>()

            pkt.addAll(listOf(0x16.toByte(), 0x03.toByte(), 0x01.toByte(), 0x00.toByte(), 0x00.toByte()))
            val handshakeStart = pkt.size
            pkt.addAll(listOf(0x01.toByte(), 0x00.toByte(), 0x00.toByte(), 0x00.toByte()))
            pkt.addAll(listOf(0x03.toByte(), 0x03.toByte()))

            for (i in 0 until 32) {
                pkt.add(((i * 37 + 11) and 0xff).toByte())
            }
            pkt.add(0x00.toByte())

            pkt.addAll(listOf(0x00.toByte(), 0x04.toByte(), 0x13.toByte(), 0x01.toByte(), 0x13.toByte(), 0x03.toByte()))
            pkt.addAll(listOf(0x01.toByte(), 0x00.toByte()))

            val extLenPos = pkt.size
            pkt.addAll(listOf(0x00.toByte(), 0x00.toByte()))
            val extStart = pkt.size

            val sniExtLen = 2 + 1 + 2 + hostBytes.size
            pkt.addAll(listOf(0x00.toByte(), 0x00.toByte(), ((sniExtLen ushr 8) and 0xff).toByte(), (sniExtLen and 0xff).toByte()))
            val listLen = 1 + 2 + hostBytes.size
            pkt.addAll(listOf(((listLen ushr 8) and 0xff).toByte(), (listLen and 0xff).toByte(), 0x00.toByte(), ((hostBytes.size ushr 8) and 0xff).toByte(), (hostBytes.size and 0xff).toByte()))
            for (b in hostBytes) pkt.add(b)

            pkt.addAll(listOf(0x00.toByte(), 0x10.toByte(), 0x00.toByte(), 0x0e.toByte(), 0x00.toByte(), 0x0c.toByte(), 0x08.toByte(), 'h'.code.toByte(), 't'.code.toByte(), 't'.code.toByte(), 'p'.code.toByte(), '/'.code.toByte(), '1'.code.toByte(), '.'.code.toByte(), '1'.code.toByte(), 0x02.toByte(), 'h'.code.toByte(), '2'.code.toByte()))

            val extLen = pkt.size - extStart
            pkt[extLenPos] = ((extLen ushr 8) and 0xff).toByte()
            pkt[extLenPos + 1] = (extLen and 0xff).toByte()

            val hsLen = pkt.size - handshakeStart - 4
            pkt[handshakeStart + 1] = ((hsLen ushr 16) and 0xff).toByte()
            pkt[handshakeStart + 2] = ((hsLen ushr 8) and 0xff).toByte()
            pkt[handshakeStart + 3] = (hsLen and 0xff).toByte()

            val recLen = pkt.size - 5
            pkt[3] = ((recLen ushr 8) and 0xff).toByte()
            pkt[4] = (recLen and 0xff).toByte()

            return pkt.toByteArray()
        }
    }
}
