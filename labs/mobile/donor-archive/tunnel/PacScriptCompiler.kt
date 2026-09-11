package com.luminet.android.tunnel

class PacScriptCompiler(val defaultProxy: String) {
    private val directDomains = mutableSetOf<String>()
    private val proxyDomains = mutableSetOf<String>()

    fun addDirectDomain(domain: String) {
        val clean = domain.trim().trimStart('.').lowercase()
        if (clean.isNotEmpty()) directDomains.add(clean)
    }

    fun addProxyDomain(domain: String) {
        val clean = domain.trim().trimStart('.').lowercase()
        if (clean.isNotEmpty()) proxyDomains.add(clean)
    }

    fun evaluateDomain(domain: String): String {
        val clean = domain.trim().trimStart('.').lowercase()
        if (directDomains.contains(clean)) return "DIRECT"
        if (proxyDomains.contains(clean)) return "PROXY $defaultProxy"

        val parts = clean.split(".")
        for (i in 1 until parts.size) {
            val sub = parts.subList(i, parts.size).joinToString(".")
            if (directDomains.contains(sub)) return "DIRECT"
            if (proxyDomains.contains(sub)) return "PROXY $defaultProxy"
        }
        return "PROXY $defaultProxy"
    }

    fun compilePac(): String {
        val sb = StringBuilder()
        sb.append("// Android PAC Engine\n")
        sb.append("function FindProxyForURL(url, host) {\n")
        sb.append("  return 'PROXY ").append(defaultProxy).append("';\n")
        sb.append("}\n")
        return sb.toString()
    }
}
