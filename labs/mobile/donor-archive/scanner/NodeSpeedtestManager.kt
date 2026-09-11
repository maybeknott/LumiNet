package com.luminet.android.scanner

import kotlinx.coroutines.*
import java.io.InputStream
import java.net.HttpURLConnection
import java.net.InetSocketAddress
import java.net.Socket
import java.net.URL
import java.util.concurrent.atomic.AtomicBoolean

/**
 * Speed benchmark actions for proxy nodes.
 */
enum class SpeedActionType {
    TCP_PING,
    REAL_PING,
    UDP_ECHO,
    SPEEDTEST
}

/**
 * Benchmark configuration parameters.
 */
data class SpeedtestConfig(
    val concurrency: Int = 4,
    val probeTimeoutMs: Int = 3000,
    val realPingUrl: String = "http://cp.cloudflare.com/generate_204",
    val speedtestUrl: String = "https://speed.cloudflare.com/__down?bytes=25000000",
    val maxDownloadBytes: Long = 25 * 1024 * 1024L
)

/**
 * Evaluation result for a specific candidate target.
 */
data class CandidateSpeedResult(
    val target: String,
    val action: SpeedActionType,
    val success: Boolean,
    val latencyMs: Long? = null,
    val downloadBytes: Long = 0L,
    val speedMbps: Double = 0.0,
    val error: String? = null
)

/**
 * High-throughput multi-action node speed evaluator for Android.
 */
class NodeSpeedtestManager(
    private val config: SpeedtestConfig = SpeedtestConfig()
) {
    private val isCancelled = AtomicBoolean(false)

    fun cancel() {
        isCancelled.set(true)
    }

    fun reset() {
        isCancelled.set(false)
    }

    /**
     * Measures direct TCP handshake RTT.
     */
    fun measureTcpPing(host: String, port: Int, timeoutMs: Int = config.probeTimeoutMs): Pair<Boolean, Long?> {
        val start = System.currentTimeMillis()
        return try {
            Socket().use { socket ->
                socket.connect(InetSocketAddress(host, port), timeoutMs)
            }
            val elapsed = System.currentTimeMillis() - start
            Pair(true, elapsed)
        } catch (e: Exception) {
            Pair(false, null)
        }
    }

    /**
     * Measures HTTP response latency (generate_204 probe).
     */
    fun measureHttpLatency(targetUrl: String = config.realPingUrl, timeoutMs: Int = config.probeTimeoutMs): Pair<Boolean, Long?> {
        val start = System.currentTimeMillis()
        var conn: HttpURLConnection? = null
        return try {
            val url = URL(targetUrl)
            conn = url.openConnection() as HttpURLConnection
            conn.connectTimeout = timeoutMs
            conn.readTimeout = timeoutMs
            conn.instanceFollowRedirects = true
            conn.requestMethod = "GET"
            conn.connect()

            val responseCode = conn.responseCode
            val elapsed = System.currentTimeMillis() - start
            if (responseCode in 200..399) {
                Pair(true, elapsed)
            } else {
                Pair(false, null)
            }
        } catch (e: Exception) {
            Pair(false, null)
        } finally {
            conn?.disconnect()
        }
    }

    /**
     * Evaluates streaming download throughput in Mbps.
     */
    fun measureDownloadThroughput(
        downloadUrl: String = config.speedtestUrl,
        maxBytes: Long = config.maxDownloadBytes,
        timeoutMs: Int = config.probeTimeoutMs * 3
    ): Triple<Boolean, Double, Long> {
        val start = System.currentTimeMillis()
        var conn: HttpURLConnection? = null
        var totalBytes = 0L

        return try {
            val url = URL(downloadUrl)
            conn = url.openConnection() as HttpURLConnection
            conn.connectTimeout = timeoutMs
            conn.readTimeout = timeoutMs
            conn.requestMethod = "GET"
            conn.connect()

            if (conn.responseCode !in 200..299) {
                return Triple(false, 0.0, 0L)
            }

            val buffer = ByteArray(16 * 1024)
            conn.inputStream.use { input ->
                while (!isCancelled.get()) {
                    val read = input.read(buffer)
                    if (read <= 0) break
                    totalBytes += read
                    if (totalBytes >= maxBytes) break
                }
            }

            val elapsedSecs = (System.currentTimeMillis() - start) / 1000.0
            val effectiveSecs = if (elapsedSecs <= 0.0) 0.001 else elapsedSecs
            val speedMbps = (totalBytes * 8.0) / (effectiveSecs * 1000.0 * 1000.0)

            Triple(true, speedMbps, totalBytes)
        } catch (e: Exception) {
            Triple(false, 0.0, totalBytes)
        } finally {
            conn?.disconnect()
        }
    }

    /**
     * Concurrently runs batch evaluation with worker dispatch.
     */
    suspend fun evaluateBatch(
        action: SpeedActionType,
        targets: List<String>,
        onProgress: ((CandidateSpeedResult) -> Unit)? = null
    ): List<CandidateSpeedResult> = withContext(Dispatchers.IO) {
        val results = mutableListOf<CandidateSpeedResult>()
        val deferredList = targets.chunked(config.concurrency).flatMap { chunk ->
            chunk.map { target ->
                async {
                    if (isCancelled.get()) {
                        return@async CandidateSpeedResult(
                            target = target,
                            action = action,
                            success = false,
                            error = "Cancelled"
                        )
                    }

                    val res = when (action) {
                        SpeedActionType.TCP_PING -> {
                            val parts = target.split(":")
                            val host = parts[0]
                            val port = if (parts.size > 1) parts[1].toIntOrNull() ?: 80 else 80
                            val (ok, lat) = measureTcpPing(host, port)
                            CandidateSpeedResult(
                                target = target,
                                action = action,
                                success = ok,
                                latencyMs = lat,
                                error = if (ok) null else "TCP connect failed"
                            )
                        }
                        SpeedActionType.REAL_PING -> {
                            val (ok, lat) = measureHttpLatency(target)
                            CandidateSpeedResult(
                                target = target,
                                action = action,
                                success = ok,
                                latencyMs = lat,
                                error = if (ok) null else "HTTP ping failed"
                            )
                        }
                        SpeedActionType.SPEEDTEST -> {
                            val (ok, speed, bytes) = measureDownloadThroughput(target)
                            CandidateSpeedResult(
                                target = target,
                                action = action,
                                success = ok,
                                speedMbps = speed,
                                downloadBytes = bytes,
                                error = if (ok) null else "Download failed"
                            )
                        }
                        SpeedActionType.UDP_ECHO -> {
                            // Fallback simulation for UDP echo on mobile platforms
                            CandidateSpeedResult(
                                target = target,
                                action = action,
                                success = false,
                                error = "UDP echo requires root or VPN socket protector"
                            )
                        }
                    }

                    onProgress?.invoke(res)
                    res
                }
            }.awaitAll()
        }

        results.addAll(deferredList)
        results
    }
}
