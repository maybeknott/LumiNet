package com.luminet.android.tunnel

import kotlinx.serialization.Serializable
import kotlinx.serialization.encodeToString
import kotlinx.serialization.json.Json

/**
 * C9.5 — orbot-android mapdns config emission.
 *
 * LumiNet can act as the "upstream DNS" for Orbot (Tor) when the user routes
 * traffic through a proxy. The mapdns protocol (documented in orbot-android)
 * allows a client to specify which domains should be resolved via the tunnel
 * vs. which should fall through to the local resolver.
 *
 * [TunMapdns] emits the JSON config that LumiNet writes into its
 * `android.net.VpnService` tun interface's `MAPDNS` extra, or as a JSON file
 * that Orbot reads when LumiNet is running in "passthrough" mode.
 *
 * ## Protocol
 *
 * Orbot expects a JSON array of [MapdnsEntry] objects. Each entry maps a
 * domain suffix (or the magic suffix `.onion`) to a resolution strategy:
 *
 *  * `direct` — resolve using the device's local resolver (DoH, DoT, or
 *    upstream from `/etc/resolv.conf`). This is the default for non-sensitive
 *    domains.
 *  * `proxy`  — resolve via the active proxy tunnel (for domains that should
 *    never leak via local DNS, e.g. domains behind domain-fronted censorship).
 *  * `block`  — return NXDOMAIN for the given domain (parental controls,
 *    split-horizon blocks, etc.).
 *
 * The wildcard syntax mirrors dnsmasq: `*.example.com` covers all subdomains.
 * Entries are evaluated top-to-bottom; the first match wins.
 */
@Serializable
data class MapdnsEntry(
    /** Domain pattern: exact (`example.com`) or wildcard (`*.example.com`). */
    val domain: String,
    /** Resolution strategy. */
    val strategy: MapdnsStrategy,
    /** Optional: explicit DNS server IP for this domain (overrides tunnel default). */
    val server: String? = null,
    /** If true, also match subdomains of [domain]. */
    val includeSubdomains: Boolean = true,
) {
    init {
        require(domain.isNotBlank()) { "domain must not be blank" }
        require(!domain.startsWith(".")) { "domain must not start with dot: $domain" }
    }

    /** Expand wildcard to the pattern form Orbot accepts. */
    fun orbotPattern(): String =
        if (domain.startsWith("*.")) domain else domain
}

@Serializable
enum class MapdnsStrategy {
    /** Resolve via the proxy tunnel. */
    proxy,

    /** Resolve via local resolver (default for non-tunnel traffic). */
    direct,

    /** Return NXDOMAIN. */
    block,
}

/**
 * Top-level config that Orbot reads. It is a JSON object with a `rules` array.
 * Compatible with the orbot-android `MAPDNS` extra JSON schema.
 */
@Serializable
data class MapdnsConfig(
    /** Format version, currently `1`. */
    val version: Int = 1,
    /** Default strategy for domains not matched by any rule. */
    val defaultStrategy: MapdnsStrategy = MapdnsStrategy.direct,
    /** Ordered list of rules; first match wins. */
    val rules: List<MapdnsEntry>,
    /** Tunnels this config applies to; empty = all. */
    val tunnelIds: List<String> = emptyList(),
    /** Human-readable description for the UI. */
    val description: String = "LumiNet mapdns config",
) {
    init {
        require(version in 1..9) { "version must be 1..9, got $version" }
    }
}

/**
 * Orbot-mapdns config emitter.
 *
 * Usage:
 * ```
 * val emitter = TunMapdns()
 * val json = emitter.emitConfig(entries)
 * // Write `json` to the VpnService MAPDNS extra or to a JSON file.
 * ```
 */
class TunMapdns {

    private val json = Json {
        ignoreUnknownKeys = true
        encodeDefaults = true
        prettyPrint = true
    }

    /**
     * Emit a complete [MapdnsConfig] as a JSON string.
     *
     * The [defaultStrategy] is applied to domains not matched by [entries];
     * pass [MapdnsStrategy.direct] for an opt-in model (domains listed in
     * [entries] are resolved via tunnel, everything else locally) or
     * [MapdnsStrategy.proxy] for an opt-out model (everything tunnels by
     * default, domains listed in [entries] with strategy `direct` fall through).
     *
     * [tunnelIds] restricts this config to specific tunnel instances; if
     * empty the config applies to all tunnels.
     */
    fun emitConfig(
        entries: List<MapdnsEntry>,
        defaultStrategy: MapdnsStrategy = MapdnsStrategy.direct,
        tunnelIds: List<String> = emptyList(),
        description: String = "LumiNet mapdns config",
    ): String {
        val config = MapdnsConfig(
            version = 1,
            defaultStrategy = defaultStrategy,
            rules = entries,
            tunnelIds = tunnelIds,
            description = description,
        )
        return json.encodeToString(config)
    }

    /**
     * Parse a JSON string back into a [MapdnsConfig]. Useful for
     * round-tripping configs stored in preferences.
     */
    fun parseConfig(jsonString: String): MapdnsConfig =
        json.decodeFromString(jsonString)

    /**
     * Convenience: build a minimal tunnel-resolve rule for a single domain.
     */
    fun tunnelRule(domain: String, includeSubdomains: Boolean = true): MapdnsEntry =
        MapdnsEntry(
            domain = domain,
            strategy = MapdnsStrategy.proxy,
            includeSubdomains = includeSubdomains,
        )

    /**
     * Convenience: build a block rule for a single domain.
     */
    fun blockRule(domain: String, includeSubdomains: Boolean = true): MapdnsEntry =
        MapdnsEntry(
            domain = domain,
            strategy = MapdnsStrategy.block,
            includeSubdomains = includeSubdomains,
        )

    /**
     * Build a sensible default config for Iran routing:
     *  * `.ir` domains → direct (resolve in country)
     *  * `.onion` → proxy (Tor)
     *  * privacy-sensitive TLDs → proxy
     *  * everything else → follows [defaultStrategy]
     */
    fun defaultIranConfig(): String = emitConfig(
        entries = listOf(
            // Iran TLDs: resolve locally to get in-country IPs.
            MapdnsEntry(domain = "ir", strategy = MapdnsStrategy.direct, includeSubdomains = true),
            MapdnsEntry(domain = "xn--fiqs8s", strategy = MapdnsStrategy.direct, includeSubdomains = true), // .中国
            MapdnsEntry(domain = "xn--fiqz9s", strategy = MapdnsStrategy.direct, includeSubdomains = true), // .中國
            // Tor: always resolve via proxy tunnel.
            MapdnsEntry(domain = "onion", strategy = MapdnsStrategy.proxy, includeSubdomains = true),
            // Privacy / censorship-candidate TLDs: proxy.
            MapdnsEntry(domain = "bit", strategy = MapdnsStrategy.proxy, includeSubdomains = true),
            MapdnsEntry(domain = "eth", strategy = MapdnsStrategy.proxy, includeSubdomains = true),
            MapdnsEntry(domain = "loki", strategy = MapdnsStrategy.proxy, includeSubdomains = true),
            MapdnsEntry(domain = "i2p", strategy = MapdnsStrategy.proxy, includeSubdomains = true),
        ),
        defaultStrategy = MapdnsStrategy.proxy, // default: tunnel everything not matched above
        description = "Iran routing default mapdns config",
    )
}
