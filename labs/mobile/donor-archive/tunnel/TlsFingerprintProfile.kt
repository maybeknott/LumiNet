package com.luminet.android.tunnel

/**
 * Browser TLS ClientHello fingerprint mimicry profile.
 * Absorbed and unified from utls-master and lumicore::evasion::fingerprint.
 */
enum class TlsFingerprintProfile(val identifier: String) {
    CHROME("chrome"),
    CHROME_120("chrome120"),
    CHROME_131("chrome131"),
    CHROME_133("chrome133"),
    FIREFOX("firefox"),
    FIREFOX_105("firefox105"),
    FIREFOX_120("firefox120"),
    SAFARI("safari"),
    SAFARI_16("safari16"),
    EDGE("edge"),
    EDGE_106("edge106"),
    IOS("ios"),
    IOS_14("ios14"),
    ANDROID_OKHTTP("android_okhttp"),
    RANDOMIZED("randomized"),
    RANDOMIZED_ALPN("randomized_alpn"),
    RANDOMIZED_NO_ALPN("randomized_no_alpn");

    companion object {
        fun fromIdentifier(id: String): TlsFingerprintProfile? =
            entries.find { it.identifier.equals(id.trim(), ignoreCase = true) }

        fun resolveLatest(browser: String): TlsFingerprintProfile = when (browser.lowercase().trim()) {
            "chrome" -> CHROME_133
            "firefox" -> FIREFOX_120
            "safari" -> SAFARI_16
            "edge" -> EDGE_106
            "ios" -> IOS_14
            "android" -> ANDROID_OKHTTP
            else -> CHROME_133
        }
    }
}

/**
 * TLS Fingerprint negotiation parameters.
 */
data class TlsFingerprintConfig(
    val profile: TlsFingerprintProfile = TlsFingerprintProfile.CHROME,
    val grease: Boolean = true,
    val permuteExtensions: Boolean = true,
    val requiredAlpn: List<String> = listOf("h2", "http/1.1")
)
