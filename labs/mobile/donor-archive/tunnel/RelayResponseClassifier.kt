package com.luminet.android.tunnel

import java.net.URI
import java.net.InetAddress

enum class PermanentFailureCategory {
    QUOTA,
    AUTH,
    DEPLOY,
    ADMIN
}

object RelayResponseClassifier {

    private val QUOTA_PATTERNS = listOf(
        "service invoked too many times",
        "invoked too many times",
        "bandwidth quota exceeded",
        "too much upload bandwidth",
        "too much traffic",
        "urlfetch",
        "quota",
        "exceeded",
        "rate limit"
    )

    private val AUTH_PATTERNS = listOf(
        "authorization is required",
        "unauthorized",
        "not authorized",
        "permission denied",
        "access denied"
    )

    private val DEPLOY_PATTERNS = listOf(
        "error code not_found",
        "not_found",
        "deployment",
        "script id",
        "scriptid",
        "no script"
    )

    private val ADMIN_PATTERNS = listOf(
        "not permitted by your admin",
        "contact your administrator",
        "disabled. please contact",
        "domain policy has disabled"
    )

    fun classifyRelayError(raw: String): String {
        val lower = raw.lowercase()

        if (lower.contains("loop detected") || lower == "loop_detected") {
            return "Relay loop detected. Your exit node URL is misconfigured."
        }

        if (QUOTA_PATTERNS.any { lower.contains(it) }) {
            return "Apps Script quota exhausted. Daily 20,000 URL-fetch or bandwidth limit reached."
        }

        if (AUTH_PATTERNS.any { lower.contains(it) }) {
            return "Apps Script rejected request (auth/permission error). Verify AUTH_KEY and deployment permissions."
        }

        if (DEPLOY_PATTERNS.any { lower.contains(it) }) {
            return "Apps Script deployment not found. Verify deployment ID."
        }

        if (ADMIN_PATTERNS.any { lower.contains(it) }) {
            return "Apps Script blocked by domain admin policy."
        }

        if (lower.contains("dns")) {
            return "DNS error in exit node. Check exit node URL."
        }

        val cleaned = raw.replace(Regex("(?i)^(Exception|Error):\\s*"), "").trim()
        return if (cleaned.isEmpty()) "Relay error: $raw" else "Relay error: $cleaned"
    }

    fun classifyPermanentFailure(raw: String): PermanentFailureCategory? {
        val lower = raw.lowercase()
        if (QUOTA_PATTERNS.any { lower.contains(it) }) return PermanentFailureCategory.QUOTA
        if (AUTH_PATTERNS.any { lower.contains(it) }) return PermanentFailureCategory.AUTH
        if (DEPLOY_PATTERNS.any { lower.contains(it) }) return PermanentFailureCategory.DEPLOY
        if (ADMIN_PATTERNS.any { lower.contains(it) }) return PermanentFailureCategory.ADMIN
        return null
    }

    fun splitSetCookie(blob: String): List<String> {
        val trimmed = blob.trim()
        if (trimmed.isEmpty()) return emptyList()

        val cookies = mutableListOf<String>()
        var currentStart = 0
        var i = 0
        val len = trimmed.length

        while (i < len) {
            if (trimmed[i] == ',') {
                var j = i + 1
                while (j < len && (trimmed[j] == ' ' || trimmed[j] == '\t')) {
                    j++
                }
                var k = j
                var hasEquals = false
                var equalsPos = 0
                while (k < len && trimmed[k] != ';' && trimmed[k] != ',') {
                    if (trimmed[k] == '=' && !hasEquals) {
                        hasEquals = true
                        equalsPos = k
                    }
                    k++
                }

                if (hasEquals) {
                    val tokenName = trimmed.substring(j, equalsPos).trim()
                    if (tokenName.isNotEmpty() && !tokenName.contains(' ') && !tokenName.contains('\t')) {
                        val cookie = trimmed.substring(currentStart, i).trim()
                        if (cookie.isNotEmpty()) {
                            cookies.add(cookie)
                        }
                        currentStart = j
                        i = j
                        continue
                    }
                }
            }
            i++
        }

        val lastCookie = trimmed.substring(currentStart).trim()
        if (lastCookie.isNotEmpty()) {
            cookies.add(lastCookie)
        }

        return cookies
    }

    fun isSafeTargetUrl(rawUrl: String): Boolean {
        return try {
            val uri = URI(rawUrl)
            val scheme = uri.scheme?.lowercase() ?: return false
            if (scheme != "http" && scheme != "https") return false

            val host = uri.host?.lowercase()?.trimEnd('.') ?: return false
            if (host.isEmpty() || host == "localhost" || host.endsWith(".local") || host.endsWith(".lan")) {
                return false
            }

            try {
                val addr = InetAddress.getByName(host)
                if (addr.isLoopbackAddress || addr.isAnyLocalAddress || addr.isLinkLocalAddress || addr.isSiteLocalAddress) {
                    return false
                }
            } catch (_: Exception) {
                // Not an IP literal or unresolvable hostname at validate time
            }

            true
        } catch (_: Exception) {
            false
        }
    }

    fun checkRelayLoop(targetUrl: String, exitHost: String, hasHopHeader: Boolean): String? {
        return try {
            val uri = URI(targetUrl)
            val targetHost = uri.host?.lowercase() ?: ""
            val targetPort = if (uri.port != -1) uri.port else if (uri.scheme?.lowercase() == "https") 443 else 80

            val cleanExit = exitHost.lowercase()
            val (exitH, exitP) = if (cleanExit.contains(":")) {
                val parts = cleanExit.split(":")
                Pair(parts[0], parts.getOrNull(1)?.toIntOrNull())
            } else {
                Pair(cleanExit, null)
            }

            if (targetHost.isNotEmpty() && exitH.isNotEmpty() && targetHost == exitH) {
                if (exitP == null || exitP == targetPort) {
                    return "loop_detected: self loop to $targetHost:$targetPort"
                }
            }

            if (hasHopHeader && (uri.path?.lowercase()?.contains("/macros/s/") == true)) {
                return "loop_detected: GAS hop loop to $targetUrl"
            }

            null
        } catch (_: Exception) {
            "malformed target URL"
        }
    }
}
