package com.luminet.android.tunnel

enum class AndroidCensorshipRegion {
    GLOBAL,
    CHINA,
    IRAN,
    RUSSIA
}

data class AndroidEvasionProfile(
    val region: AndroidCensorshipRegion,
    val dnsFragmentationEnabled: Boolean,
    val dnsFragmentSize: Int,
    val tcpMssClamp: Int,
    val tlsPaddingMin: Int,
    val tlsPaddingMax: Int,
    val parallelDnsQueries: Boolean,
    val preferredDnsServers: List<String>
)

class CensorshipProfileSynthesizer {
    private val profiles = mutableMapOf<AndroidCensorshipRegion, AndroidEvasionProfile>()

    init {
        profiles[AndroidCensorshipRegion.CHINA] = AndroidEvasionProfile(
            region = AndroidCensorshipRegion.CHINA,
            dnsFragmentationEnabled = true,
            dnsFragmentSize = 40,
            tcpMssClamp = 1200,
            tlsPaddingMin = 100,
            tlsPaddingMax = 500,
            parallelDnsQueries = true,
            preferredDnsServers = listOf("https://cloudflare-dns.com/dns-query", "https://dns.google/dns-query")
        )

        profiles[AndroidCensorshipRegion.IRAN] = AndroidEvasionProfile(
            region = AndroidCensorshipRegion.IRAN,
            dnsFragmentationEnabled = true,
            dnsFragmentSize = 32,
            tcpMssClamp = 1100,
            tlsPaddingMin = 256,
            tlsPaddingMax = 1024,
            parallelDnsQueries = true,
            preferredDnsServers = listOf("https://sky.rethinkdns.com/dns-query", "https://dns.quad9.net/dns-query")
        )

        profiles[AndroidCensorshipRegion.RUSSIA] = AndroidEvasionProfile(
            region = AndroidCensorshipRegion.RUSSIA,
            dnsFragmentationEnabled = false,
            dnsFragmentSize = 0,
            tcpMssClamp = 1300,
            tlsPaddingMin = 64,
            tlsPaddingMax = 256,
            parallelDnsQueries = true,
            preferredDnsServers = listOf("https://1.1.1.1/dns-query")
        )

        profiles[AndroidCensorshipRegion.GLOBAL] = AndroidEvasionProfile(
            region = AndroidCensorshipRegion.GLOBAL,
            dnsFragmentationEnabled = false,
            dnsFragmentSize = 0,
            tcpMssClamp = 1460,
            tlsPaddingMin = 0,
            tlsPaddingMax = 0,
            parallelDnsQueries = false,
            preferredDnsServers = listOf("https://1.1.1.1/dns-query")
        )
    }

    fun getProfile(region: AndroidCensorshipRegion): AndroidEvasionProfile {
        return profiles[region] ?: profiles[AndroidCensorshipRegion.GLOBAL]!!
    }
}
