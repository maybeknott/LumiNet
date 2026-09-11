// Copyright 2024-2026 LumiNet Authors. All Rights Reserved.
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

package com.luminet.android.tunnel

import java.nio.charset.StandardCharsets
import java.security.MessageDigest
import java.security.SecureRandom
import javax.crypto.Cipher
import javax.crypto.spec.IvParameterSpec
import javax.crypto.spec.SecretKeySpec

/**
 * Tunnel protocol actions dispatched between agent and server.
 */
enum class DecoyAction(val wireName: String) {
    OPEN("open"),
    REQUEST("request"),
    SEND("send"),
    RECV("recv"),
    CLOSE("close");

    companion object {
        fun fromWire(value: String): DecoyAction {
            val normalized = value.trim().lowercase()
            return entries.find { it.wireName == normalized } ?: OPEN
        }
    }
}

/**
 * Configuration parameters for HTTP decoy tunnel framing and encryption.
 */
data class DecoyTunnelConfig(
    val token: String = "af445adb-2434-4975-9445-2c1b2231",
    val fakeUrls: List<String> = listOf(
        "nipo.ciron.net",
        "sudoer.ir",
        "sudoer.net",
        "google.com",
        "cloudflare.com"
    ),
    val methods: List<String> = listOf("GET", "POST", "PUT", "DELETE"),
    val endpoints: List<String> = listOf("api", "login", "user", "update"),
    val userAgent: String = "Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:132.0) Gecko/20100101 Firefox/132.0",
    val httpVersion: String = "1.1",
    val bufferSize: Int = 65536,
    val connectionReuse: Boolean = true,
    val tunnelEnable: Boolean = false,
    val timeoutSec: Int = 10,
    val pullTimeoutMs: Int = 1
) {
    /**
     * Derives a 32-byte AES key from the configured token.
     */
    fun deriveKey(): ByteArray {
        val tokenBytes = token.toByteArray(StandardCharsets.UTF_8)
        return if (tokenBytes.size == 32) {
            tokenBytes.copyOf(32)
        } else {
            val md = MessageDigest.getInstance("SHA-256")
            md.digest(tokenBytes)
        }
    }

    fun cleanHostHeader(fakeUrl: String): String {
        var host = fakeUrl
        val schemeIdx = host.indexOf("://")
        if (schemeIdx != -1) {
            host = host.substring(schemeIdx + 3)
        }
        val slashIdx = host.indexOf('/')
        if (slashIdx != -1) {
            host = host.substring(0, slashIdx)
        }
        return host
    }

    fun selectFakeUrl(seed: Int): String {
        if (fakeUrls.isEmpty()) return "cloudflare.com"
        val idx = Math.floorMod(seed, fakeUrls.size)
        return fakeUrls[idx]
    }

    fun selectMethod(seed: Int): String {
        if (methods.isEmpty()) return "POST"
        val idx = Math.floorMod(seed, methods.size)
        return methods[idx]
    }

    fun selectEndpoint(seed: Int): String {
        if (endpoints.isEmpty()) return "api"
        val idx = Math.floorMod(seed, endpoints.size)
        return endpoints[idx]
    }
}

/**
 * Cryptographic envelope providing AES-256-CBC encryption, decryption, hex, and base64 transforms.
 */
object DecoyEnvelope {
    private val secureRandom = SecureRandom()

    fun encrypt(plaintext: ByteArray, key: ByteArray): ByteArray {
        val iv = ByteArray(16)
        secureRandom.nextBytes(iv)

        val cipher = Cipher.getInstance("AES/CBC/PKCS5Padding")
        val secretKeySpec = SecretKeySpec(key, "AES")
        val ivParameterSpec = IvParameterSpec(iv)
        cipher.init(Cipher.ENCRYPT_MODE, secretKeySpec, ivParameterSpec)

        val encrypted = cipher.doFinal(plaintext)
        val result = ByteArray(16 + encrypted.size)
        System.arraycopy(iv, 0, result, 0, 16)
        System.arraycopy(encrypted, 0, result, 16, encrypted.size)
        return result
    }

    fun decrypt(dataWithIv: ByteArray, key: ByteArray): ByteArray {
        require(dataWithIv.size >= 32) { "Ciphertext must be at least 32 bytes (16-byte IV + block)" }

        val iv = dataWithIv.copyOfRange(0, 16)
        val ciphertext = dataWithIv.copyOfRange(16, dataWithIv.size)

        val cipher = Cipher.getInstance("AES/CBC/PKCS5Padding")
        val secretKeySpec = SecretKeySpec(key, "AES")
        val ivParameterSpec = IvParameterSpec(iv)
        cipher.init(Cipher.DECRYPT_MODE, secretKeySpec, ivParameterSpec)

        return cipher.doFinal(ciphertext)
    }

    fun toHex(bytes: ByteArray): String {
        val sb = java.lang.StringBuilder(bytes.size * 2)
        for (b in bytes) {
            sb.append(String.format("%02x", b.toInt() and 0xFF))
        }
        return sb.toString()
    }

    fun fromHex(hexStr: String): ByteArray {
        val trimmed = hexStr.trim()
        require(trimmed.length % 2 == 0) { "Invalid hex string length" }
        val len = trimmed.length / 2
        val out = ByteArray(len)
        for (i in 0 until len) {
            val high = Character.digit(trimmed[i * 2], 16)
            val low = Character.digit(trimmed[i * 2 + 1], 16)
            require(high != -1 && low != -1) { "Invalid hex characters" }
            out[i] = ((high shl 4) or low).toByte()
        }
        return out
    }

    fun toBase64(bytes: ByteArray): String {
        return java.util.Base64.getEncoder().encodeToString(bytes)
    }

    fun fromBase64(str: String): ByteArray {
        return java.util.Base64.getDecoder().decode(str.trim())
    }
}

/**
 * Inbound parsed HTTP decoy request.
 */
data class DecoyHttpRequest(
    val method: String,
    val path: String,
    val version: String,
    val host: String,
    val userAgent: String,
    val sessionId: String,
    val action: DecoyAction,
    val contentLength: Int,
    val keepAlive: Boolean,
    val headers: Map<String, String>,
    val rawBody: ByteArray
) {
    override fun equals(other: Any?): Boolean {
        if (this === other) return true
        if (javaClass != other?.javaClass) return false
        other as DecoyHttpRequest
        return sessionId == other.sessionId && action == other.action && rawBody.contentEquals(other.rawBody)
    }

    override fun hashCode(): Int {
        var result = sessionId.hashCode()
        result = 31 * result + action.hashCode()
        result = 31 * result + rawBody.contentHashCode()
        return result
    }
}

/**
 * Inbound parsed HTTP decoy response.
 */
data class DecoyHttpResponse(
    val version: String,
    val statusCode: Int,
    val statusText: String,
    val contentLength: Int,
    val keepAlive: Boolean,
    val headers: Map<String, String>,
    val rawBody: ByteArray
) {
    override fun equals(other: Any?): Boolean {
        if (this === other) return true
        if (javaClass != other?.javaClass) return false
        other as DecoyHttpResponse
        return statusCode == other.statusCode && rawBody.contentEquals(other.rawBody)
    }

    override fun hashCode(): Int {
        var result = statusCode.hashCode()
        result = 31 * result + rawBody.contentHashCode()
        return result
    }
}

/**
 * Codec for formatting and parsing HTTP decoy frames.
 */
class DecoyHttpCodec(private val config: DecoyTunnelConfig = DecoyTunnelConfig()) {

    /**
     * Encodes agent request: hex-encodes payload -> AES-256-CBC encrypts -> Base64 encodes -> formats HTTP request.
     */
    fun encodeAgentRequest(
        sessionId: String,
        action: DecoyAction,
        innerPayload: ByteArray,
        seed: Int = 0
    ): ByteArray {
        val key = config.deriveKey()

        // 1. Payload to Hex
        val hexPayload = DecoyEnvelope.toHex(innerPayload)

        // 2. Encrypt hex bytes
        val encrypted = DecoyEnvelope.encrypt(hexPayload.toByteArray(StandardCharsets.UTF_8), key)

        // 3. Base64
        val b64Body = DecoyEnvelope.toBase64(encrypted)

        val fakeUrl = config.selectFakeUrl(seed)
        val hostHeader = config.cleanHostHeader(fakeUrl)
        val method = config.selectMethod(seed)
        val endpoint = config.selectEndpoint(seed)
        val conn = if (config.connectionReuse || action == DecoyAction.OPEN) "keep-alive" else "close"

        val sb = java.lang.StringBuilder()
        sb.append("$method /$endpoint HTTP/${config.httpVersion}\r\n")
        sb.append("Host: $hostHeader\r\n")
        sb.append("User-Agent: ${config.userAgent}\r\n")
        sb.append("Accept: */*\r\n")
        sb.append("Content-Type: application/text\r\n")
        sb.append("X-Nipo-Session: $sessionId\r\n")
        sb.append("X-Nipo-Action: ${action.wireName}\r\n")
        sb.append("Content-Length: ${b64Body.length}\r\n")
        sb.append("Connection: $conn\r\n")
        sb.append("\r\n")
        sb.append(b64Body)

        return sb.toString().toByteArray(StandardCharsets.UTF_8)
    }

    /**
     * Decodes server request: extracts headers, Base64 decodes, AES-256-CBC decrypts, hex decodes payload.
     */
    fun decodeServerRequest(rawHttp: ByteArray): Pair<DecoyHttpRequest, ByteArray> {
        val rawStr = String(rawHttp, StandardCharsets.UTF_8)
        val headerEnd = rawStr.indexOf("\r\n\r\n")
        require(headerEnd != -1) { "Incomplete HTTP request: missing header terminator" }

        val headerPart = rawStr.substring(0, headerEnd)
        val bodyPart = rawStr.substring(headerEnd + 4)

        val lines = headerPart.split("\r\n")
        require(lines.isNotEmpty()) { "Empty HTTP request" }

        val reqParts = lines[0].split(" ")
        require(reqParts.size >= 3) { "Invalid HTTP request line" }

        val method = reqParts[0]
        val path = reqParts[1]
        val version = reqParts[2].removePrefix("HTTP/")

        val headers = mutableMapOf<String, String>()
        var sessionId = ""
        var action = DecoyAction.OPEN
        var contentLength = 0
        var keepAlive = true
        var host = ""
        var userAgent = ""

        for (i in 1 until lines.size) {
            val line = lines[i]
            val colonIdx = line.indexOf(':')
            if (colonIdx != -1) {
                val name = line.substring(0, colonIdx).trim().lowercase()
                val value = line.substring(colonIdx + 1).trim()
                headers[name] = value

                when (name) {
                    "host" -> host = value
                    "user-agent" -> userAgent = value
                    "x-nipo-session" -> sessionId = value
                    "x-nipo-action" -> action = DecoyAction.fromWire(value)
                    "content-length" -> contentLength = value.toIntOrNull() ?: 0
                    "connection" -> keepAlive = value.lowercase().contains("keep-alive")
                }
            }
        }

        val actualBody = if (contentLength > 0 && bodyPart.length > contentLength) {
            bodyPart.substring(0, contentLength)
        } else {
            bodyPart
        }

        var innerPayload = ByteArray(0)
        val trimmedBody = actualBody.trim()
        if (trimmedBody.isNotEmpty()) {
            val key = config.deriveKey()
            val ciphertext = DecoyEnvelope.fromBase64(trimmedBody)
            val hexBytes = DecoyEnvelope.decrypt(ciphertext, key)
            val hexStr = String(hexBytes, StandardCharsets.UTF_8)
            innerPayload = DecoyEnvelope.fromHex(hexStr)
        }

        val request = DecoyHttpRequest(
            method = method,
            path = path,
            version = version,
            host = host,
            userAgent = userAgent,
            sessionId = sessionId,
            action = action,
            contentLength = contentLength,
            keepAlive = keepAlive,
            headers = headers,
            rawBody = actualBody.toByteArray(StandardCharsets.UTF_8)
        )

        return Pair(request, innerPayload)
    }

    /**
     * Formats server response with AES-256-CBC encrypted payload.
     */
    fun encodeServerResponse(
        statusCode: Int,
        statusText: String,
        plainBody: ByteArray,
        keepAlive: Boolean = true
    ): ByteArray {
        val key = config.deriveKey()
        val encryptedBody = if (plainBody.isNotEmpty()) {
            DecoyEnvelope.encrypt(plainBody, key)
        } else {
            ByteArray(0)
        }

        val conn = if (keepAlive) "keep-alive" else "close"
        val header = "HTTP/1.1 $statusCode $statusText\r\n" +
                "Content-Type: application/text\r\n" +
                "Content-Length: ${encryptedBody.size}\r\n" +
                "Connection: $conn\r\n" +
                "Cache-Control: no-cache\r\n" +
                "Pragma: no-cache\r\n" +
                "\r\n"

        val headerBytes = header.toByteArray(StandardCharsets.UTF_8)
        val response = ByteArray(headerBytes.size + encryptedBody.size)
        System.arraycopy(headerBytes, 0, response, 0, headerBytes.size)
        System.arraycopy(encryptedBody, 0, response, headerBytes.size, encryptedBody.size)
        return response
    }

    /**
     * Decodes and decrypts server response received on the agent.
     */
    fun decodeAgentResponse(rawHttp: ByteArray): Pair<DecoyHttpResponse, ByteArray> {
        val doubleCrlf = "\r\n\r\n".toByteArray(StandardCharsets.UTF_8)
        var headerEnd = -1
        for (i in 0 until rawHttp.size - 3) {
            if (rawHttp[i] == doubleCrlf[0] &&
                rawHttp[i + 1] == doubleCrlf[1] &&
                rawHttp[i + 2] == doubleCrlf[2] &&
                rawHttp[i + 3] == doubleCrlf[3]
            ) {
                headerEnd = i
                break
            }
        }
        require(headerEnd != -1) { "Incomplete HTTP response: missing header terminator" }

        val headerStr = String(rawHttp.copyOfRange(0, headerEnd), StandardCharsets.UTF_8)
        val bodyBytes = rawHttp.copyOfRange(headerEnd + 4, rawHttp.size)

        val lines = headerStr.split("\r\n")
        require(lines.isNotEmpty()) { "Empty HTTP response" }

        val statusParts = lines[0].split(" ")
        require(statusParts.size >= 2) { "Invalid HTTP status line" }

        val version = statusParts[0].removePrefix("HTTP/")
        val statusCode = statusParts[1].toInt()
        val statusText = if (statusParts.size > 2) statusParts.subList(2, statusParts.size).joinToString(" ") else "OK"

        val headers = mutableMapOf<String, String>()
        var contentLength = 0
        var keepAlive = true

        for (i in 1 until lines.size) {
            val line = lines[i]
            val colonIdx = line.indexOf(':')
            if (colonIdx != -1) {
                val name = line.substring(0, colonIdx).trim().lowercase()
                val value = line.substring(colonIdx + 1).trim()
                headers[name] = value

                when (name) {
                    "content-length" -> contentLength = value.toIntOrNull() ?: 0
                    "connection" -> keepAlive = value.lowercase().contains("keep-alive")
                }
            }
        }

        val actualBody = if (contentLength > 0 && bodyBytes.size > contentLength) {
            bodyBytes.copyOfRange(0, contentLength)
        } else {
            bodyBytes
        }

        val decryptedPayload = if (actualBody.isNotEmpty()) {
            val key = config.deriveKey()
            DecoyEnvelope.decrypt(actualBody, key)
        } else {
            ByteArray(0)
        }

        val response = DecoyHttpResponse(
            version = version,
            statusCode = statusCode,
            statusText = statusText,
            contentLength = contentLength,
            keepAlive = keepAlive,
            headers = headers,
            rawBody = actualBody
        )

        return Pair(response, decryptedPayload)
    }
}

/**
 * Manages thread-safe session telemetry and state for Android client.
 */
class DecoySessionTracker(val sessionId: String) {
    @Volatile
    var isConnected: Boolean = false
        private set

    @Volatile
    var bytesSent: Long = 0L
        private set

    @Volatile
    var bytesReceived: Long = 0L
        private set

    @Volatile
    var activeAction: DecoyAction = DecoyAction.OPEN
        private set

    fun markConnected() {
        isConnected = true
        activeAction = DecoyAction.SEND
    }

    fun recordSent(bytes: Int) {
        bytesSent += bytes.toLong()
    }

    fun recordReceived(bytes: Int) {
        bytesReceived += bytes.toLong()
    }

    fun markClosed() {
        isConnected = false
        activeAction = DecoyAction.CLOSE
    }
}
