package com.luminet.android.security

import java.security.MessageDigest
import javax.net.ssl.SSLPeerUnverifiedException
import javax.net.ssl.SSLSession
import javax.net.ssl.X509TrustManager
import java.security.cert.X509Certificate
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.withContext
import kotlinx.serialization.Serializable
import kotlinx.serialization.encodeToString
import kotlinx.serialization.json.Json

/**
 * C9.2 — v2rayNG certificate SHA-256 pinning flow.
 *
 * v2rayNG stores the SHA-256 of the leaf certificate (or its SubjectPublicKeyInfo,
 * configured per profile) alongside each remote. [CertPinningFlow] is the
 * Android-side helper that:
 *
 *  1. Computes a [CertPin] from a raw [X509Certificate].
 *  2. Verifies a live [SSLSession] against a [PinningConfig].
 *  3. Emits a [PinningConfig] JSON blob that the user can paste into a
 *     v2rayNG profile's `certSha256` field.
 *
 * Pin format: lowercase hex, no colons, 64 chars. This matches the
 * v2rayNG convention so a copy/paste round-trip never fails.
 */
@Serializable
data class CertPin(
    /** Subject DN, used for human inspection only. */
    val subject: String,
    /** Issuer DN, used for human inspection only. */
    val issuer: String,
    /** SHA-256 of the DER-encoded certificate (not the SPKI). */
    val certSha256: String,
    /** SHA-256 of the SubjectPublicKeyInfo (matches v2rayNG certSha256). */
    val spkiSha256: String,
    /** Not-after instant, epoch millis. */
    val notAfterMillis: Long,
) {
    init {
        require(certSha256.length == 64) { "certSha256 must be 64 hex chars, got ${certSha256.length}" }
        require(spkiSha256.length == 64) { "spkiSha256 must be 64 hex chars, got ${spkiSha256.length}" }
        require(certSha256.all { it in "0123456789abcdef" }) { "certSha256 must be lowercase hex" }
        require(spkiSha256.all { it in "0123456789abcdef" }) { "spkiSha256 must be lowercase hex" }
    }

    /** Returns the pin string in v2rayNG format. */
    fun v2rayNgPin(): String = spkiSha256
}

@Serializable
data class PinningConfig(
    /** Profile identifier this pinning config belongs to. */
    val profileId: String,
    /** Acceptable pins for the leaf. */
    val leafPins: List<String>,
    /** Acceptable pins for an intermediate (optional). */
    val intermediatePins: List<String> = emptyList(),
    /** Backup pins; used when leaf+intermediate fail (key rotation). */
    val backupPins: List<String> = emptyList(),
    /** Expiry epoch millis; 0 = no expiry. */
    val expiresAtMillis: Long = 0L,
    /** Pretty-printed policy string for the UI. */
    val policy: String = "strict",
) {
    init {
        require(leafPins.isNotEmpty()) { "At least one leaf pin is required" }
        require(leafPins.all { it.length == 64 }) { "All pins must be 64-char hex" }
        require(policy in setOf("strict", "lenient", "off")) { "policy must be strict/lenient/off" }
    }

    fun toV2rayNgConfigJson(): String = JSON.encodeToString(this)
}

/** Pinning verification outcome. */
sealed class PinResult {
    data class Ok(val matched: String) : PinResult()
    data class Mismatch(val expected: List<String>, val actual: String) : PinResult()
    data object NoPeerCertificates : PinResult()
    data object Expired : PinResult()
    data object Disabled : PinResult()
}

private val JSON: Json = Json {
    ignoreUnknownKeys = true
    encodeDefaults = true
    prettyPrint = true
}

/**
 * v2rayNG-compatible certificate pinning flow.
 *
 * Thread-safety: stateless. Safe to call from any coroutine.
 */
class CertPinningFlow {

    /**
     * Compute a [CertPin] from a raw certificate. Suspending because some
     * platforms (API 30+) defer DN parsing to the platform provider.
     */
    suspend fun pinCertificate(cert: X509Certificate): CertPin = withContext(Dispatchers.IO) {
        val certSha256 = sha256(cert.encoded)
        val spki = cert.publicKey.encoded
        val spkiSha256 = sha256(spki)
        CertPin(
            subject = cert.subjectX500Principal.name,
            issuer = cert.issuerX500Principal.name,
            certSha256 = certSha256,
            spkiSha256 = spkiSha256,
            notAfterMillis = cert.notAfter.time,
        )
    }

    /**
     * Verify a [SSLSession] against [config]. Returns a structured result so
     * the caller can render a precise error in the UI rather than a generic
     * `SSLHandshakeException`.
     */
    suspend fun verifyPinnedCert(session: SSLSession, config: PinningConfig): PinResult = withContext(Dispatchers.IO) {
        if (config.policy == "off") return@withContext PinResult.Disabled
        if (config.expiresAtMillis > 0 && config.expiresAtMillis < System.currentTimeMillis()) {
            return@withContext PinResult.Expired
        }
        val peerCerts = try {
            session.peerCertificates
        } catch (e: SSLPeerUnverifiedException) {
            return@withContext PinResult.NoPeerCertificates
        }
        if (peerCerts.isEmpty()) return@withContext PinResult.NoPeerCertificates

        val chain = peerCerts.filterIsInstance<X509Certificate>()
        val leaf = chain.first()
        val intermediates = chain.drop(1)

        val leafPin = sha256(leaf.encoded)
        if (leafPin in config.leafPins) {
            return@withContext PinResult.Ok(matched = leafPin)
        }
        // Try intermediate matches.
        intermediates.firstOrNull { sha256(it.encoded) in config.intermediatePins }
            ?.let { return@withContext PinResult.Ok(matched = sha256(it.encoded)) }
        // Last resort: backup pins (key rotation window).
        chain.firstOrNull { sha256(it.encoded) in config.backupPins }
            ?.let { return@withContext PinResult.Ok(matched = sha256(it.encoded)) }
        PinResult.Mismatch(expected = config.leafPins, actual = leafPin)
    }

    /**
     * Build a [PinningConfig] from one or more observed pins. The first pin
     * is treated as primary; the rest become backup pins (one-week expiry).
     */
    fun pinningConfigFor(
        profileId: String,
        primary: CertPin,
        backups: List<CertPin> = emptyList(),
        expiryMillis: Long = System.currentTimeMillis() + 7L * 24 * 3_600_000,
    ): PinningConfig = PinningConfig(
        profileId = profileId,
        leafPins = listOf(primary.spkiSha256) + backups.map { it.spkiSha256 },
        expiresAtMillis = expiryMillis,
        policy = "strict",
    )

    private fun sha256(der: ByteArray): String =
        MessageDigest.getInstance("SHA-256").digest(der).joinToString("") { "%02x".format(it) }
}
