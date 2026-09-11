package com.luminet.android.tunnel

import org.json.JSONArray
import org.json.JSONObject

/**
 * Resolved outbound classification type.
 */
enum class CoreResolvedType {
    NORMAL,
    POLICYGROUP,
    PROXYCHAIN
}

/**
 * Outbound profile metadata item.
 */
data class OutboundProfileItem(
    val guid: String,
    val remarks: String,
    val server: String,
    val port: Int,
    val protocol: String = "vless",
    val proxyChainProfiles: String? = null,
    val isCustom: Boolean = false
)

/**
 * Routing ruleset rule item.
 */
data class RoutingRuleItem(
    val enabled: Boolean = true,
    val domain: List<String> = emptyList(),
    val ip: List<String> = emptyList(),
    val outboundTag: String = "proxy"
)

/**
 * Domain rule normalized for DNS classification.
 */
data class NormalizedDomainRule(
    val domains: List<String>,
    val outboundTag: String
)

/**
 * Fully resolved outbound specification.
 */
data class ResolvedOutbound(
    val tag: String,
    val profile: OutboundProfileItem,
    val resolvedProfiles: List<OutboundProfileItem>,
    val resolvedType: CoreResolvedType
)

/**
 * Core runtime configuration context.
 */
data class CoreConfigContext(
    val guid: String,
    val isCustom: Boolean = false,
    val resolvedOutbounds: List<ResolvedOutbound> = emptyList(),
    val routingDomainRules: List<NormalizedDomainRule> = emptyList()
)

/**
 * Runtime configuration context compiler for Android.
 */
object CoreConfigContextBuilder {

    /**
     * Builds a fully analyzed and resolved configuration context.
     */
    fun build(
        guid: String,
        profiles: Map<String, OutboundProfileItem>,
        rules: List<RoutingRuleItem> = emptyList()
    ): CoreConfigContext? {
        val primaryProfile = profiles[guid] ?: return null
        if (primaryProfile.isCustom) {
            return CoreConfigContext(guid = guid, isCustom = true)
        }

        val primaryOutbound = resolveOutbound("proxy", primaryProfile, profiles) ?: return null
        val routingOutbounds = resolveRoutingOutbounds(rules, profiles)
        val domainRules = collectRoutingDomainRules(rules)

        return CoreConfigContext(
            guid = guid,
            isCustom = false,
            resolvedOutbounds = listOf(primaryOutbound) + routingOutbounds,
            routingDomainRules = domainRules
        )
    }

    /**
     * Resolves an individual outbound profile into normal or proxy chain form.
     */
    fun resolveOutbound(
        tag: String,
        profile: OutboundProfileItem,
        profiles: Map<String, OutboundProfileItem>
    ): ResolvedOutbound? {
        if (profile.isCustom) return null

        val chainProfiles = resolveProxyChainProfiles(profile, profiles)
        val type = if (chainProfiles.size <= 1) CoreResolvedType.NORMAL else CoreResolvedType.PROXYCHAIN

        return ResolvedOutbound(
            tag = tag,
            profile = profile,
            resolvedProfiles = chainProfiles,
            resolvedType = type
        )
    }

    /**
     * Resolves multi-hop proxy chains from comma-separated remark references.
     */
    private fun resolveProxyChainProfiles(
        profile: OutboundProfileItem,
        profiles: Map<String, OutboundProfileItem>
    ): List<OutboundProfileItem> {
        val chainString = profile.proxyChainProfiles
        if (chainString.isNullOrBlank()) {
            return listOf(profile)
        }

        val remarks = chainString.split(",").map { it.trim() }.filter { it.isNotEmpty() }
        val remarkMap = profiles.values.associateBy { it.remarks }

        val chain = mutableListOf<OutboundProfileItem>()
        for (remark in remarks) {
            remarkMap[remark]?.let { chain.add(it) }
        }
        chain.add(profile)
        return chain
    }

    /**
     * Resolves non-builtin routing outbounds.
     */
    private fun resolveRoutingOutbounds(
        rules: List<RoutingRuleItem>,
        profiles: Map<String, OutboundProfileItem>
    ): List<ResolvedOutbound> {
        val builtin = setOf("proxy", "direct", "block", "dns-out")
        val result = mutableListOf<ResolvedOutbound>()
        val seenTags = mutableSetOf<String>()
        val remarkMap = profiles.values.associateBy { it.remarks }

        for (rule in rules) {
            if (!rule.enabled || rule.outboundTag.isBlank() || rule.outboundTag in builtin) {
                continue
            }
            if (seenTags.contains(rule.outboundTag)) continue
            seenTags.add(rule.outboundTag)

            val profile = remarkMap[rule.outboundTag] ?: continue
            val resolved = resolveOutbound(rule.outboundTag, profile, profiles) ?: continue
            result.add(resolved)
        }

        return result
    }

    /**
     * Normalizes domain rules for DNS segmentation into proxy / direct / block tags.
     */
    fun collectRoutingDomainRules(rules: List<RoutingRuleItem>): List<NormalizedDomainRule> {
        return rules.filter { it.enabled && it.domain.isNotEmpty() }.map { rule ->
            val tag = when (rule.outboundTag) {
                "direct" -> "direct"
                "block" -> "block"
                else -> "proxy"
            }
            NormalizedDomainRule(rule.domain, tag)
        }
    }

    /**
     * Strips non-essential components to produce a fast latency probing config.
     */
    fun stripConfigForSpeedtest(
        fullConfigJson: String,
        targetOutboundTag: String,
        probeListenPort: Int
    ): String {
        val full = JSONObject(fullConfigJson)
        val fullOutbounds = full.optJSONArray("outbounds") ?: JSONArray()

        val selectedOutbounds = JSONArray()
        for (i in 0 until fullOutbounds.length()) {
            val ob = fullOutbounds.getJSONObject(i)
            val tag = ob.optString("tag")
            if (tag == targetOutboundTag || tag == "direct") {
                selectedOutbounds.put(ob)
            }
        }

        val testInbound = JSONObject().apply {
            put("tag", "speedtest_inbound")
            put("listen", "127.0.0.1")
            put("port", probeListenPort)
            put("protocol", "socks")
            put("settings", JSONObject().apply {
                put("auth", "noauth")
                put("udp", false)
            })
        }

        val testRule = JSONObject().apply {
            put("type", "field")
            put("inboundTag", JSONArray().put("speedtest_inbound"))
            put("outboundTag", targetOutboundTag)
        }

        val speedConfig = JSONObject().apply {
            put("log", JSONObject().put("loglevel", "warning"))
            put("inbounds", JSONArray().put(testInbound))
            put("outbounds", selectedOutbounds)
            put("routing", JSONObject().apply {
                put("domainStrategy", "AsIs")
                put("rules", JSONArray().put(testRule))
            })
        }

        return speedConfig.toString()
    }
}
