package com.luminet.android.importing

import java.security.MessageDigest
import kotlinx.serialization.Serializable
import kotlinx.serialization.encodeToString
import kotlinx.serialization.json.Json

/**
 * C9.1 — v2rayNG re-import identity matching.
 *
 * A [ProfileKey] is a stable, content-derived identifier for an imported
 * proxy / VPN profile. Two v2rayNG exports that share the same logical
 * configuration MUST produce the same [ProfileKey] regardless of cosmetic
 * differences (whitespace, field order, alias renames).
 *
 * The key is computed as a SHA-256 over a canonicalized JSON projection
 * that strips [alias] (display-only) and only keeps routing-relevant
 * fields ([protocol], [host], [port], [uuid], [password], [network],
 * [security], [path], [sni]).
 */
@Serializable
data class ProfileKey(
    /** Hex-encoded SHA-256 (lowercase, 64 chars). */
    val hash: String,
    /** Source scheme (vmess://, vless://, trojan://, ss://, hysteria://, etc.). */
    val protocol: String,
    /** Hostname or IP literal. */
    val host: String,
    /** Network port. */
    val port: Int,
    /** Optional user identifier (UUID, password, etc.). */
    val identity: String? = null,
    /** Transport (tcp / ws / grpc / h2 / quic). */
    val transport: String = "tcp",
    /** TLS variant (none / tls / reality). */
    val security: String = "none",
) {
    init {
        require(hash.length == 64) { "ProfileKey.hash must be a 64-char hex SHA-256, got ${hash.length}" }
        require(port in 0..65535) { "ProfileKey.port out of range: $port" }
        require(protocol.isNotBlank()) { "ProfileKey.protocol must not be blank" }
    }

    /**
     * Returns a short, human-stable identifier (first 12 hex chars of the
     * hash) suitable for list UIs where a full 64-char key is unreadable.
     */
    fun shortHash(): String = hash.substring(0, 12)

    override fun toString(): String = "ProfileKey(${protocol}://$host:$port, ${shortHash()}…)"
}

/**
 * Canonical JSON used as the input to the SHA-256 hash. Field order is fixed
 * and `alias` is intentionally omitted so that cosmetic renames do not
 * change the identity.
 */
internal val canonicalJson: Json = Json {
    ignoreUnknownKeys = true
    encodeDefaults = true
    prettyPrint = false
    explicitNulls = false
    coerceInputValues = true
}

/**
 * Compute a [ProfileKey] for a v2rayNG import record. The [alias] parameter
 * is intentionally NOT part of the key; the identity of a profile lives in
 * its connection parameters, not its label.
 *
 * @throws IllegalArgumentException for blank protocol/host or out-of-range port.
 */
fun computeProfileKey(profile: V2rayProfile): ProfileKey {
    require(profile.protocol.isNotBlank()) { "protocol must not be blank" }
    require(profile.host.isNotBlank()) { "host must not be blank" }
    require(profile.port in 0..65535) { "port out of range: ${profile.port}" }

    val canonical = CanonicalProjection(
        protocol = profile.protocol.trim().lowercase(),
        host = profile.host.trim().lowercase(),
        port = profile.port,
        uuid = profile.uuid?.trim()?.lowercase(),
        password = profile.password?.trim(),
        network = profile.network?.trim()?.lowercase() ?: "tcp",
        tls = profile.tls?.trim()?.lowercase() ?: "none",
        path = profile.path?.trim(),
        sni = profile.sni?.trim()?.lowercase(),
    )

    val bytes = canonicalJson.encodeToString(canonical).toByteArray(Charsets.UTF_8)
    val digest = MessageDigest.getInstance("SHA-256").digest(bytes)
    val hex = digest.joinToString(separator = "") { "%02x".format(it) }

    return ProfileKey(
        hash = hex,
        protocol = canonical.protocol,
        host = canonical.host,
        port = canonical.port,
        identity = canonical.uuid ?: canonical.password,
        transport = canonical.network,
        security = canonical.tls,
    )
}

/**
 * Decide whether [incoming] should be merged into [existing] in the user's
 * profile list. Returns [MatchDecision.MATCH] only when both keys are
 * equal; this is the contract the import flow relies on to deduplicate
 * v2rayNG re-imports.
 */
fun matchProfile(existing: ProfileKey, incoming: ProfileKey): MatchDecision {
    if (existing.hash != incoming.hash) {
        return MatchDecision.MISMATCH
    }
    // Same hash, but verify the structural fields agree — defence in depth
    // against a future hash-function swap that produces the same digest
    // length for different inputs (e.g. SHA-256 truncation bugs).
    if (existing.protocol != incoming.protocol ||
        existing.host != incoming.host ||
        existing.port != incoming.port
    ) {
        return MatchDecision.MISMATCH
    }
    return MatchDecision.MATCH
}

/** Result of a [matchProfile] comparison. */
enum class MatchDecision { MATCH, MISMATCH }

/** Raw v2rayNG import shape — the alias is intentionally optional. */
@Serializable
data class V2rayProfile(
    val protocol: String,
    val host: String,
    val port: Int,
    val uuid: String? = null,
    val password: String? = null,
    val network: String? = null,
    val tls: String? = null,
    val path: String? = null,
    val sni: String? = null,
    val alias: String? = null,
)

/** Canonical projection used as the input to the SHA-256 digest. */
@Serializable
private data class CanonicalProjection(
    val protocol: String,
    val host: String,
    val port: Int,
    val uuid: String? = null,
    val password: String? = null,
    val network: String,
    val tls: String,
    val path: String? = null,
    val sni: String? = null,
)
