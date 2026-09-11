package com.luminet.android.tunnel

data class ParsedOvpnProfile(
    var remoteHost: String = "",
    var remotePort: Int = 1194,
    var proto: String = "udp",
    var dev: String = "tun",
    var cipher: String = "AES-256-GCM",
    var auth: String = "SHA256",
    var caCert: String = "",
    var clientCert: String = "",
    var clientKey: String = "",
    val routes: MutableList<String> = mutableListOf()
)

class OvpnConfigTranspiler {

    fun transpile(raw: String): ParsedOvpnProfile? {
        val lines = raw.lines()
        val profile = ParsedOvpnProfile()
        var currentTag: String? = null
        val tagBuffer = StringBuilder()

        for (line in lines) {
            val trimmed = line.trim()
            if (trimmed.isEmpty() || trimmed.startsWith("#") || trimmed.startsWith(";")) continue

            if (trimmed.startsWith("<") && trimmed.endsWith(">") && !trimmed.startsWith("</")) {
                currentTag = trimmed.substring(1, trimmed.length - 1)
                tagBuffer.clear()
                continue
            }

            if (currentTag != null && trimmed == "</$currentTag>") {
                when (currentTag) {
                    "ca" -> profile.caCert = tagBuffer.toString().trim()
                    "cert" -> profile.clientCert = tagBuffer.toString().trim()
                    "key" -> profile.clientKey = tagBuffer.toString().trim()
                }
                currentTag = null
                continue
            }

            if (currentTag != null) {
                tagBuffer.append(trimmed).append("\n")
                continue
            }

            val tokens = trimmed.split("\\s+".toRegex())
            if (tokens.isEmpty()) continue

            when (tokens[0]) {
                "remote" -> {
                    if (tokens.size >= 2) profile.remoteHost = tokens[1]
                    if (tokens.size >= 3) profile.remotePort = tokens[2].toIntOrNull() ?: 1194
                    if (tokens.size >= 4) profile.proto = tokens[3].lowercase()
                }
                "proto" -> if (tokens.size >= 2) profile.proto = tokens[1].lowercase()
                "dev" -> if (tokens.size >= 2) profile.dev = tokens[1]
                "cipher" -> if (tokens.size >= 2) profile.cipher = tokens[1]
                "auth" -> if (tokens.size >= 2) profile.auth = tokens[1]
                "route" -> if (tokens.size >= 2) profile.routes.add(tokens.drop(1).joinToString(" "))
            }
        }

        if (profile.remoteHost.isEmpty()) return null
        return profile
    }
}
