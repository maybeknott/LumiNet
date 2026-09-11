package com.luminet.android.subscription

import kotlinx.serialization.Serializable
import kotlinx.serialization.encodeToString
import kotlinx.serialization.json.Json

/**
 * C9.4 — v2rayNG subscription refresh diffing.
 *
 * A v2rayNG subscription URL resolves to a base64 blob containing one
 * profile per line (v2rayNG custom format, not the URI spec). When the user
 * taps "refresh", LumiNet fetches the new blob and compares it against the
 * previously stored snapshot.
 *
 * [SubscriptionDiff] computes the minimal diff so the UI can render an
 * incremental change list (added / removed / modified) rather than dumping
 * the full new list every time.
 *
 * Identity is established via [SubscriptionItem.hash]; entries with the same
 * hash are considered the same profile regardless of their position or label.
 * Position changes (reorder) are NOT reported as diff events since they carry
 * no semantic change in the v2rayNG model.
 */

/** A single line from the decoded subscription blob. */
@Serializable
data class SubscriptionItem(
    /** Profile display name (alias). */
    val alias: String,
    /** Connection protocol (vmess / vless / trojan / ss). */
    val protocol: String,
    /** Remote address (hostname or IP). */
    val host: String,
    /** Remote port. */
    val port: Int,
    /** UUID / password / secret. */
    val identity: String? = null,
    /** Transport type (tcp / ws / grpc / h2 / quic). */
    val transport: String = "tcp",
    /** TLS variant (none / tls / reality). */
    val tls: String = "none",
    /** SHA-256 of the normalised connection string; used as stable identity. */
    val hash: String,
) {
    init {
        require(port in 0..65535) { "port out of range: $port" }
        require(hash.length == 64) { "hash must be 64 hex chars" }
    }
}

/** Result of [SubscriptionDiff.diff]. */
sealed class Diff {
    abstract val newItems: List<SubscriptionItem>
    abstract val removedItems: List<SubscriptionItem>
    abstract val modifiedItems: List<Pair<SubscriptionItem, SubscriptionItem>>

    /** Items present in [new] but not in [old]. */
    data class Added(
        override val newItems: List<SubscriptionItem>,
        override val removedItems: List<SubscriptionItem> = emptyList(),
        override val modifiedItems: List<Pair<SubscriptionItem, SubscriptionItem>> = emptyList(),
    ) : Diff()

    /** Items present in [old] but not in [new]. */
    data class Removed(
        override val newItems: List<SubscriptionItem> = emptyList(),
        override val removedItems: List<SubscriptionItem>,
        override val modifiedItems: List<Pair<SubscriptionItem, SubscriptionItem>> = emptyList(),
    ) : Diff()

    /** Items that share a hash but differ in non-identity fields. */
    data class Modified(
        override val newItems: List<SubscriptionItem> = emptyList(),
        override val removedItems: List<SubscriptionItem> = emptyList(),
        override val modifiedItems: List<Pair<SubscriptionItem, SubscriptionItem>>,
    ) : Diff()

    /** Nothing changed. */
    data object Unchanged : Diff() {
        override val newItems: List<SubscriptionItem> = emptyList()
        override val removedItems: List<SubscriptionItem> = emptyList()
        override val modifiedItems: List<Pair<SubscriptionItem, SubscriptionItem>> = emptyList()
    }

    /** Mixed: some items added, removed, or modified. */
    data class Mixed(
        override val newItems: List<SubscriptionItem>,
        override val removedItems: List<SubscriptionItem>,
        override val modifiedItems: List<Pair<SubscriptionItem, SubscriptionItem>>,
    ) : Diff()

    /** True if any change occurred. */
    val hasChanges: Boolean get() = this !is Unchanged

    /** Human-readable summary. */
    fun summary(): String = when (this) {
        is Unchanged -> "No changes"
        is Added -> "+${newItems.size} added"
        is Removed -> "-${removedItems.size} removed"
        is Modified -> "~${modifiedItems.size} modified"
        is Mixed -> "+${newItems.size} added, -${removedItems.size} removed, ~${modifiedItems.size} modified"
    }
}

/** Subscription refresh diffing engine. */
class SubscriptionDiff {

    private val json = Json {
        ignoreUnknownKeys = true
        coerceInputValues = true
        encodeDefaults = true
    }

    /**
     * Compute the diff between two subscription snapshots.
     *
     * Algorithm:
     *  1. Build identity maps from [old] and [new] keyed by hash.
     *  2. Classify each hash: only-in-old → Removed, only-in-new → Added,
     *     in-both → compare fields; if any differ → Modified.
     *  3. Return the most specific [Diff] variant (Unchanged → Added →
     *     Removed → Modified → Mixed).
     */
    fun diff(old: List<SubscriptionItem>, new: List<SubscriptionItem>): Diff {
        val oldMap = old.associateBy { it.hash }
        val newMap = new.associateBy { it.hash }

        val added = new.filter { it.hash !in oldMap }
        val removed = old.filter { it.hash !in newMap }

        val modified = mutableListOf<Pair<SubscriptionItem, SubscriptionItem>>()
        for ((hash, newItem) in newMap) {
            val oldItem = oldMap[hash] ?: continue
            if (oldItem.copy(hash = "").toCanonical() != newItem.copy(hash = "").toCanonical()) {
                modified += oldItem to newItem
            }
        }

        return when {
            added.isEmpty() && removed.isEmpty() && modified.isEmpty() -> Diff.Unchanged
            added.isNotEmpty() && removed.isEmpty() && modified.isEmpty() -> Diff.Added(newItems = added)
            added.isEmpty() && removed.isNotEmpty() && modified.isEmpty() -> Diff.Removed(removedItems = removed)
            added.isEmpty() && removed.isEmpty() && modified.isNotEmpty() -> Diff.Modified(modifiedItems = modified)
            else -> Diff.Mixed(newItems = added, removedItems = removed, modifiedItems = modified)
        }
    }

    /**
     * Parse a v2rayNG subscription blob into [SubscriptionItem] list.
     * The blob is base64-encoded, one profile per line, JSON objects with
     * v2rayNG's internal field names.
     */
    fun parse(lines: List<String>): List<SubscriptionItem> = lines.mapIndexedNotNull { index, line ->
        try {
            val parsed = json.decodeFromString<RawSubscriptionItem>(line)
            SubscriptionItem(
                alias = parsed.remark ?: "Profile ${index + 1}",
                protocol = parsed.protocol,
                host = parsed.add,
                port = parsed.port,
                identity = parsed.id ?: parsed.password,
                transport = parsed.net,
                tls = parsed.tls,
                hash = parsed.computeHash(),
            )
        } catch (e: Exception) {
            null // skip malformed lines
        }
    }

    /**
     * Parse a raw v2rayNG base64 blob into [SubscriptionItem] list.
     * Convenience wrapper around [parse].
     */
    fun parseFromBase64(base64: String): List<SubscriptionItem> {
        val decoded = android.util.Base64.decode(base64, android.util.Base64.NO_WRAP)
        val text = String(decoded, Charsets.UTF_8)
        val lines = text.lineSequence()
            .map { it.trim() }
            .filter { it.isNotBlank() }
            .toList()
        return parse(lines)
    }

    private fun SubscriptionItem.toCanonical(): String {
        // Same fields used for the hash — identity fields only.
        return "$protocol|$host|$port|$identity|$transport|$tls"
    }

    private fun RawSubscriptionItem.computeHash(): String {
        val text = "$protocol|$add|$port|$id|$net|$tls"
        val digest = java.security.MessageDigest.getInstance("SHA-256").digest(text.toByteArray())
        return digest.joinToString("") { "%02x".format(it) }
    }
}

/** Internal v2rayNG JSON shape. */
@Serializable
private data class RawSubscriptionItem(
    val v: String? = null,
    val ps: String? = null,
    val remark: String? = null,
    val add: String = "",
    val port: Int = 0,
    val id: String? = null,
    val net: String = "tcp",
    val type: String? = null,
    val host: String? = null,
    val path: String? = null,
    val tls: String = "none",
    val protocol: String = "",
    val password: String? = null,
    val aid: String? = null,
    val scy: String? = null,
    val sni: String? = null,
    val alpn: String? = null,
    val fp: String? = null,
)
