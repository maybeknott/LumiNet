package com.luminet.android.tunnel

enum class AndroidToolchainTarget {
    GIT,
    PIP,
    NPM,
    GRADLE,
    CURL,
    DOCKER,
    ENV
}

class ToolchainProxyWrapper(
    val httpProxy: String,
    val socks5Proxy: String
) {
    fun generateEnvVars(): Map<String, String> {
        return mapOf(
            "http_proxy" to httpProxy,
            "https_proxy" to httpProxy,
            "HTTP_PROXY" to httpProxy,
            "HTTPS_PROXY" to httpProxy,
            "ALL_PROXY" to socks5Proxy,
            "all_proxy" to socks5Proxy,
            "NO_PROXY" to "localhost,127.0.0.1,::1"
        )
    }

    fun generateSnippet(target: AndroidToolchainTarget): String {
        return when (target) {
            AndroidToolchainTarget.GIT -> "[http]\n\tproxy = $httpProxy\n[https]\n\tproxy = $httpProxy\n"
            AndroidToolchainTarget.PIP -> "[global]\nproxy = $httpProxy\n"
            AndroidToolchainTarget.NPM -> "proxy=$httpProxy\nhttps-proxy=$httpProxy\n"
            AndroidToolchainTarget.GRADLE -> {
                val clean = httpProxy.removePrefix("http://")
                val parts = clean.split(":")
                val host = parts.getOrNull(0) ?: "127.0.0.1"
                val port = parts.getOrNull(1) ?: "8080"
                "systemProp.http.proxyHost=$host\nsystemProp.http.proxyPort=$port\nsystemProp.https.proxyHost=$host\nsystemProp.https.proxyPort=$port\n"
            }
            AndroidToolchainTarget.CURL -> "proxy = \"$socks5Proxy\"\n"
            AndroidToolchainTarget.DOCKER -> "{\n  \"proxies\": {\n    \"default\": {\n      \"httpProxy\": \"$httpProxy\",\n      \"httpsProxy\": \"$httpProxy\"\n    }\n  }\n}\n"
            AndroidToolchainTarget.ENV -> "export HTTP_PROXY=\"$httpProxy\"\nexport HTTPS_PROXY=\"$httpProxy\"\nexport ALL_PROXY=\"$socks5Proxy\"\n"
        }
    }
}
