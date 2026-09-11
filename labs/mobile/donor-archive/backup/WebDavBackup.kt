package com.luminet.android.backup

import java.io.BufferedReader
import java.io.InputStream
import java.io.InputStreamReader
import java.io.OutputStream
import java.net.HttpURLConnection
import java.net.URL
import java.net.URLEncoder
import java.text.SimpleDateFormat
import java.util.Date
import java.util.Locale
import java.util.TimeZone
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.withContext
import kotlinx.serialization.Serializable
import kotlinx.serialization.encodeToString
import kotlinx.serialization.json.Json

/**
 * C9.3 — v2rayNG WebDAV backup.
 *
 * v2rayNG stores remote backups on a WebDAV endpoint; each backup is a
 * single file `v2rayng_<timestamp>.zip`. [WebDavBackup] is a thin,
 * dependency-free client that supports:
 *
 *  * PUT (upload) of a backup blob.
 *  * GET  (download) of the most recent backup.
 *  * PROPFIND (list) of all backups under a remote directory.
 *  * MKCOL (ensure the remote directory exists).
 *
 * It mirrors the wire format v2rayNG uses (RFC 4918 + ISO-8601 timestamps
 * with millisecond precision) so that a backup written by v2rayNG can be
 * read by LumiNet and vice-versa.
 */
@Serializable
data class WebDavConfig(
    val endpoint: String,
    val username: String,
    val password: String,
    val remoteDir: String = "/LumiNet-Backups",
    val connectTimeoutMs: Int = 10_000,
    val readTimeoutMs: Int = 30_000,
    val userAgent: String = "LumiNet-Android/1.0",
) {
    init {
        require(endpoint.startsWith("http://") || endpoint.startsWith("https://")) {
            "endpoint must be http(s)://..."
        }
        require(remoteDir.startsWith("/")) { "remoteDir must be absolute, got $remoteDir" }
    }

    /** Base URL for the configured remote directory. */
    fun directoryUrl(): String = endpoint.trimEnd('/') + remoteDir
}

@Serializable
data class BackupManifest(
    val version: Int,
    val createdAtMillis: Long,
    val profileCount: Int,
    val sha256: String,
    val sourceApp: String = "LumiNet-Android",
    val originalV2rayNgFilename: String? = null,
) {
    fun toJson(): String = JSON.encodeToString(this)
}

@Serializable
data class BackupListing(val entries: List<RemoteBackup>)

@Serializable
data class RemoteBackup(
    val name: String,
    val href: String,
    val size: Long,
    val lastModifiedMillis: Long,
)

/** Result wrapper so the UI can render errors without try/catch. */
sealed class BackupResult<out T> {
    data class Success<T>(val value: T) : BackupResult<T>()
    data class Failure(val status: Int, val message: String) : BackupResult<Nothing>()
}

/**
 * Stateless WebDAV client. Each call opens a fresh [HttpURLConnection] so
 * the flow is safe to invoke from any coroutine.
 */
class WebDavBackup {

    private val httpPropfindBody = """<?xml version="1.0" encoding="utf-8" ?>
        <D:propfind xmlns:D="DAV:">
          <D:prop>
            <D:getlastmodified/>
            <D:getcontentlength/>
            <D:resourcetype/>
          </D:prop>
        </D:propfind>""".trimIndent()

    /** Ensure the remote directory exists (MKCOL). Idempotent. */
    suspend fun ensureDirectory(config: WebDavConfig): BackupResult<Unit> = withContext(Dispatchers.IO) {
        execute(config, config.directoryUrl(), "MKCOL") { conn ->
            // 201 = created, 405 = already exists, both are success.
            if (conn.responseCode in setOf(201, 405)) {
                BackupResult.Success(Unit)
            } else {
                BackupResult.Failure(conn.responseCode, "MKCOL failed: ${conn.responseCode}")
            }
        }
    }

    /** Upload a backup blob. The returned [RemoteBackup] is the canonical name. */
    suspend fun upload(
        config: WebDavConfig,
        bytes: ByteArray,
        manifest: BackupManifest,
    ): BackupResult<RemoteBackup> = withContext(Dispatchers.IO) {
        val ts = ISO8601.format(Date(manifest.createdAtMillis))
        val name = "luminet_${ts}.zip"
        val url = config.directoryUrl().trimEnd('/') + "/" + URLEncoder.encode(name, "UTF-8")
        execute(config, url, "PUT") { conn ->
            conn.doOutput = true
            conn.setRequestProperty("Content-Type", "application/zip")
            conn.setRequestProperty("X-LumiNet-Manifest", manifest.toJson())
            conn.outputStream.use { it.write(bytes) }
            val code = conn.responseCode
            when {
                code in 200..299 -> BackupResult.Success(
                    RemoteBackup(name, url, bytes.size.toLong(), manifest.createdAtMillis)
                )
                else -> BackupResult.Failure(code, "PUT failed: $code")
            }
        }
    }

    /** Download a specific backup. */
    suspend fun download(
        config: WebDavConfig,
        name: String,
    ): BackupResult<ByteArray> = withContext(Dispatchers.IO) {
        val url = config.directoryUrl().trimEnd('/') + "/" + URLEncoder.encode(name, "UTF-8")
        execute(config, url, "GET") { conn ->
            if (conn.responseCode == 200) {
                BackupResult.Success(conn.inputStream.readBytes())
            } else {
                BackupResult.Failure(conn.responseCode, "GET failed: ${conn.responseCode}")
            }
        }
    }

    /** PROPFIND — list all backups under the configured directory. */
    suspend fun list(config: WebDavConfig): BackupResult<BackupListing> = withContext(Dispatchers.IO) {
        execute(config, config.directoryUrl(), "PROPFIND") { conn ->
            conn.setRequestProperty("Depth", "1")
            conn.doOutput = true
            conn.outputStream.use { it.write(httpPropfindBody.toByteArray(Charsets.UTF_8)) }
            val code = conn.responseCode
            if (code !in 200..299) {
                return@execute BackupResult.Failure(code, "PROPFIND failed: $code")
            }
            val text = conn.inputStream.bufferedReader().use(BufferedReader::readText)
            val entries = parsePropfind(text, config.directoryUrl())
            BackupResult.Success(BackupListing(entries.sortedByDescending { it.lastModifiedMillis }))
        }
    }

    /**
     * Download the most recent backup by combining [list] + [download].
     * Returns null if no backups exist.
     */
    suspend fun downloadLatest(config: WebDavConfig): BackupResult<ByteArray?> = withContext(Dispatchers.IO) {
        when (val listing = list(config)) {
            is BackupResult.Failure -> listing
            is BackupResult.Success -> {
                val latest = listing.value.entries.firstOrNull()
                    ?: return@withContext BackupResult.Success(null)
                download(config, latest.name)
            }
        }
    }

    private fun <T> execute(
        config: WebDavConfig,
        url: String,
        method: String,
        block: (HttpURLConnection) -> BackupResult<T>,
    ): BackupResult<T> {
        val conn = (URL(url).openConnection() as HttpURLConnection).apply {
            requestMethod = method
            connectTimeout = config.connectTimeoutMs
            readTimeout = config.readTimeoutMs
            setRequestProperty("User-Agent", config.userAgent)
            val creds = "${config.username}:${config.password}"
            val basic = android.util.Base64.encodeToString(creds.toByteArray(), android.util.Base64.NO_WRAP)
            setRequestProperty("Authorization", "Basic $basic")
        }
        return try {
            block(conn)
        } catch (e: Exception) {
            BackupResult.Failure(-1, "${e::class.simpleName}: ${e.message}")
        } finally {
            conn.disconnect()
        }
    }

    private fun parsePropfind(xml: String, baseHref: String): List<RemoteBackup> {
        val entries = mutableListOf<RemoteBackup>()
        val responseRegex = Regex(
            """<D:response[^>]*>([\s\S]*?)</D:response>""",
            RegexOption.IGNORE_CASE,
        )
        for (match in responseRegex.findAll(xml)) {
            val body = match.groupValues[1]
            val href = Regex("""<D:href>([^<]+)</D:href>""", RegexOption.IGNORE_CASE)
                .find(body)?.groupValues?.get(1) ?: continue
            if (href == baseHref || href.trimEnd('/') == baseHref.trimEnd('/')) continue
            val size = Regex("""<D:getcontentlength>([0-9]+)</D:getcontentlength>""", RegexOption.IGNORE_CASE)
                .find(body)?.groupValues?.get(1)?.toLongOrNull() ?: 0L
            val lm = Regex("""<D:getlastmodified>([^<]+)</D:getlastmodified>""", RegexOption.IGNORE_CASE)
                .find(body)?.groupValues?.get(1) ?: continue
            val millis = parseHttpDate(lm) ?: continue
            val name = href.substringAfterLast('/')
            entries += RemoteBackup(name = name, href = href, size = size, lastModifiedMillis = millis)
        }
        return entries
    }

    private fun parseHttpDate(s: String): Long? {
        return try {
            val fmt = SimpleDateFormat("EEE, dd MMM yyyy HH:mm:ss zzz", Locale.US)
            fmt.timeZone = TimeZone.getTimeZone("GMT")
            fmt.parse(s)?.time
        } catch (_: Exception) {
            null
        }
    }

    companion object {
        private val ISO8601: SimpleDateFormat = SimpleDateFormat("yyyyMMdd'T'HHmmss'Z'", Locale.US).apply {
            timeZone = TimeZone.getTimeZone("UTC")
        }
        private val JSON: Json = Json {
            ignoreUnknownKeys = true
            encodeDefaults = true
            prettyPrint = true
        }
    }
}
