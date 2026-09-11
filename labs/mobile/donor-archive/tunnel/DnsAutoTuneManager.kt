package com.luminet.android.tunnel

import java.util.Base64
import org.json.JSONObject

enum class AutoTunePresetStability {
    STABLE,
    AGGRESSIVE
}

data class DnsAutoTunePreset(
    val id: String,
    val label: String,
    val minUploadMtu: Int,
    val maxUploadMtu: Int,
    val minDownloadMtu: Int,
    val maxDownloadMtu: Int,
    val resolverTimeoutMs: Long,
    val dnsFragCapacity: Int,
    val uploadDuplication: Int,
    val downloadDuplication: Int,
    val uploadCompression: Int,
    val downloadCompression: Int,
    val stability: AutoTunePresetStability = AutoTunePresetStability.STABLE
)

object DnsAutoTunePresets {
    val all: List<DnsAutoTunePreset> = listOf(
        DnsAutoTunePreset("iran-average", "Iran Default", 40, 140, 300, 3000, 2500, 256, 3, 7, 2, 2),
        DnsAutoTunePreset("iran-low-mtu-scan", "Iran Low MTU Scan", 20, 120, 160, 768, 2500, 256, 3, 7, 2, 2),
        DnsAutoTunePreset("iran-fast-low-mtu", "Iran Fast Low MTU", 20, 325, 100, 1270, 2500, 100, 5, 10, 2, 2),
        DnsAutoTunePreset("iran-compact-fixed", "Iran Compact Fixed", 62, 62, 414, 414, 2500, 384, 6, 8, 2, 2),
        DnsAutoTunePreset("iran-fixed-64-balanced", "Iran Fixed 64 Balanced", 64, 64, 756, 756, 2500, 256, 8, 8, 2, 2),
        DnsAutoTunePreset("iran-mid-reliable", "Iran Mid Reliable", 120, 160, 652, 1110, 2500, 256, 5, 11, 2, 2),
        DnsAutoTunePreset("iran-download-heavy", "Iran Download Heavy", 104, 139, 394, 1000, 2500, 256, 8, 30, 2, 2),
        DnsAutoTunePreset("iran-fixed-64-aggressive", "Iran Fixed 64 Wide", 64, 64, 756, 1317, 2500, 230, 14, 30, 2, 2, AutoTunePresetStability.AGGRESSIVE),
        DnsAutoTunePreset("iran-large-download-aggressive", "Iran No Compression Max", 100, 600, 800, 6500, 2500, 640, 23, 30, 0, 0, AutoTunePresetStability.AGGRESSIVE),
        DnsAutoTunePreset("iran-wide-range-aggressive", "Iran Wide Range Max", 100, 1000, 200, 2667, 2500, 256, 15, 30, 2, 2, AutoTunePresetStability.AGGRESSIVE),
    )

    fun getById(id: String): DnsAutoTunePreset? = all.find { it.id == id }
}

fun chunkResolversRoundRobin(
    resolvers: List<String>,
    requestedWorkerCount: Int
): List<List<String>> {
    val clean = resolvers.map { it.trim() }.filter { it.isNotEmpty() }
    if (clean.isEmpty()) return emptyList()

    val workerCount = requestedWorkerCount.coerceAtLeast(1).coerceAtMost(clean.size)
    val chunks = List(workerCount) { mutableListOf<String>() }
    clean.forEachIndexed { idx, resolver ->
        chunks[idx % workerCount].add(resolver)
    }
    return chunks.map { it.toList() }
}

data class DnsProfileRecord(
    val name: String,
    val domain: String,
    val encryptionKey: String,
    val encryptionMethod: Int,
    val engine: String = "stormdns"
)

object DnsProfileLinkManager {

    fun encode(record: DnsProfileRecord): String {
        require(record.domain.isNotBlank()) { "Domain is required" }
        require(record.encryptionKey.isNotBlank()) { "Encryption key is required" }

        val serverObj = JSONObject()
            .put("domain", record.domain.trim().trimEnd('.'))
            .put("encryption_key", record.encryptionKey.trim())
            .put("encryption_method", record.encryptionMethod.coerceIn(0, 5))

        val profileObj = JSONObject()
            .put("name", record.name.ifBlank { record.domain })
            .put("server", serverObj)

        val root = JSONObject()
            .put("schema", "whitedns.profile")
            .put("version", 1)
            .put("profile", profileObj)

        val b64 = Base64.getUrlEncoder().withoutPadding().encodeToString(root.toString().toByteArray(Charsets.UTF_8))
        val scheme = record.engine.ifBlank { "stormdns" }
        return "$scheme://$b64"
    }

    fun decode(link: String): DnsProfileRecord {
        val parts = link.split("://")
        require(parts.size == 2) { "Invalid profile URI format" }
        val engine = parts[0].lowercase()
        val rawPayload = parts[1].substringBefore('#').substringBefore('?').trim()
        require(rawPayload.isNotBlank()) { "Empty profile payload" }

        val padded = rawPayload.padEnd(rawPayload.length + ((4 - rawPayload.length % 4) % 4), '=')
        val bytes = runCatching {
            Base64.getUrlDecoder().decode(padded)
        }.recoverCatching {
            Base64.getDecoder().decode(padded)
        }.getOrThrow()

        val root = JSONObject(String(bytes, Charsets.UTF_8))
        require(root.optString("schema") == "whitedns.profile") { "Unsupported schema" }

        val profileObj = root.getJSONObject("profile")
        val serverObj = profileObj.getJSONObject("server")

        return DnsProfileRecord(
            name = profileObj.getString("name"),
            domain = serverObj.getString("domain"),
            encryptionKey = serverObj.getString("encryption_key"),
            encryptionMethod = serverObj.getInt("encryption_method"),
            engine = engine
        )
    }
}
