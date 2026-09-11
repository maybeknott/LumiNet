package com.luminet.android.security

/**
 * Manages MITM Domain Fronting (MMDF) routing, local decryption port mapping,
 * and multi-SAN certificate validation.
 * Conforms to §8 structural rules.
 */
sealed class MitmAction {
    object Direct : MitmAction()
    object Block : MitmAction()
    data class RedirectToMitm(val port: Int) : MitmAction()
    data class RepackFronted(
        val frontedSni: String,
        val allowedSans: List<String>,
        val redirectEndpoint: String? = null,
        val alpn: List<String>,
    ) : MitmAction()
}

data class FrontingProfile(
    val name: String,
    val frontedSni: String,
    val allowedSans: List<String>,
    val redirectEndpoint: String? = null,
    val alpn: List<String>,
)

object MitmFrontingManager {
    const val DEFAULT_H11_PORT = 11666
    const val DEFAULT_H211_PORT = 11777

    val GOOGLE_VIDEO_PROFILE = FrontingProfile(
        name = "google-video",
        frontedSni = "www.google.com",
        allowedSans = listOf(
            "www.google.com",
            "*.google.com",
            "dns.google",
            "www.googlevideo.com",
            "*.googlevideo.com",
            "www.youtube.com",
            "*.youtube.com",
        ),
        alpn = listOf("http/1.1"),
    )

    val GOOGLE_PROFILE = FrontingProfile(
        name = "google",
        frontedSni = "www.google.com",
        allowedSans = listOf(
            "www.google.com",
            "*.google.com",
            "dns.google",
            "www.googlevideo.com",
            "*.googlevideo.com",
            "www.youtube.com",
            "*.youtube.com",
        ),
        alpn = listOf("h2", "http/1.1"),
    )

    val FASTLY_PROFILE = FrontingProfile(
        name = "fastly",
        frontedSni = "github.githubassets.com",
        redirectEndpoint = "github.githubassets.com:443",
        allowedSans = listOf(
            "github.githubassets.com",
            "githubassets.com",
            "*.githubassets.com",
            "github.com",
            "*.github.com",
            "fastly.com",
            "*.fastly.com",
            "reddit.com",
            "*.reddit.com",
            "pypi.org",
            "*.python.org",
        ),
        alpn = listOf("h2", "http/1.1"),
    )

    val META_PROFILE = FrontingProfile(
        name = "meta",
        frontedSni = "www.microsoft.com",
        allowedSans = listOf(
            "www.whatsapp.com",
            "*.whatsapp.com",
            "*.whatsapp.net",
            "www.facebook.com",
            "*.facebook.com",
            "*.fbcdn.net",
            "www.instagram.com",
            "*.instagram.com",
            "*.cdninstagram.com",
            "*.meta.com",
        ),
        alpn = listOf("h2", "http/1.1"),
    )

    private val PROFILES = listOf(GOOGLE_VIDEO_PROFILE, GOOGLE_PROFILE, FASTLY_PROFILE, META_PROFILE)

    fun routeIngress(
        domain: String,
        isVideo: Boolean = false,
        h11Port: Int = DEFAULT_H11_PORT,
        h211Port: Int = DEFAULT_H211_PORT,
    ): MitmAction {
        val d = domain.trim().lowercase()

        // Direct bypass
        if (d.endsWith(".ir") || d == "localhost" || d == "127.0.0.1") {
            return MitmAction.Direct
        }

        // Video streaming traffic routes to H1.1 port
        if (isVideo || d.contains("googlevideo.com")) {
            return MitmAction.RedirectToMitm(h11Port)
        }

        // Frontable domains route to H2/H1.1 port
        if (isFrontableDomain(d)) {
            return MitmAction.RedirectToMitm(h211Port)
        }

        return MitmAction.Direct
    }

    fun routeDecryptedEgress(
        domain: String,
        inboundPort: Int,
        h11Port: Int = DEFAULT_H11_PORT,
        h211Port: Int = DEFAULT_H211_PORT,
    ): MitmAction {
        val d = domain.trim().lowercase()

        if (inboundPort == h11Port) {
            if (d.contains("googlevideo.com")) {
                return MitmAction.RepackFronted(
                    frontedSni = GOOGLE_VIDEO_PROFILE.frontedSni,
                    allowedSans = GOOGLE_VIDEO_PROFILE.allowedSans,
                    redirectEndpoint = GOOGLE_VIDEO_PROFILE.redirectEndpoint,
                    alpn = GOOGLE_VIDEO_PROFILE.alpn,
                )
            }
            return MitmAction.Block
        }

        if (inboundPort == h211Port) {
            if (d.contains("google") || d.contains("youtube")) {
                return MitmAction.RepackFronted(
                    frontedSni = GOOGLE_PROFILE.frontedSni,
                    allowedSans = GOOGLE_PROFILE.allowedSans,
                    redirectEndpoint = GOOGLE_PROFILE.redirectEndpoint,
                    alpn = GOOGLE_PROFILE.alpn,
                )
            }

            if (d.contains("fastly") || d.contains("reddit") || d.contains("github") || d.contains("pypi")) {
                return MitmAction.RepackFronted(
                    frontedSni = FASTLY_PROFILE.frontedSni,
                    allowedSans = FASTLY_PROFILE.allowedSans,
                    redirectEndpoint = FASTLY_PROFILE.redirectEndpoint,
                    alpn = FASTLY_PROFILE.alpn,
                )
            }

            if (d.contains("meta") || d.contains("facebook") || d.contains("instagram") || d.contains("whatsapp")) {
                return MitmAction.RepackFronted(
                    frontedSni = META_PROFILE.frontedSni,
                    allowedSans = META_PROFILE.allowedSans,
                    redirectEndpoint = META_PROFILE.redirectEndpoint,
                    alpn = META_PROFILE.alpn,
                )
            }

            return MitmAction.Block
        }

        return MitmAction.Direct
    }

    fun matchSanPattern(presented: String, pattern: String): Boolean {
        val pres = presented.trim().lowercase()
        val pat = pattern.trim().lowercase()

        if (pres == pat) return true

        if (pat.startsWith("*.")) {
            val suffix = pat.removePrefix("*.")
            if (pres.endsWith(suffix) && pres.length > suffix.length) {
                val prefix = pres.removeSuffix(suffix)
                if (prefix.endsWith(".") && !prefix.dropLast(1).contains(".")) {
                    return true
                }
            }
        }
        return false
    }

    fun verifyPeerSans(presentedSans: List<String>, allowedSans: List<String>): Boolean {
        for (presented in presentedSans) {
            for (allowed in allowedSans) {
                if (matchSanPattern(presented, allowed)) return true
            }
        }
        return false
    }

    private fun isFrontableDomain(domain: String): Boolean {
        for (prof in PROFILES) {
            for (allowed in prof.allowedSans) {
                if (matchSanPattern(domain, allowed)) return true
            }
        }
        return false
    }
}
