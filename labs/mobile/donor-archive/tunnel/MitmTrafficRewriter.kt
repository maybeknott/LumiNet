package com.luminet.android.tunnel

sealed class AndroidRewriteAction {
    data class RedirectUrl(val newUrl: String) : AndroidRewriteAction()
    data class SetHeader(val name: String, val value: String) : AndroidRewriteAction()
    data class RemoveHeader(val name: String) : AndroidRewriteAction()
    data class ReplaceBody(val pattern: String, val replacement: String) : AndroidRewriteAction()
}

data class AndroidRewriteRule(
    val ruleId: String,
    val domainPattern: String,
    val pathPrefix: String,
    val isActive: Boolean = true,
    val action: AndroidRewriteAction
)

class MitmTrafficRewriter {
    private val rules = mutableListOf<AndroidRewriteRule>()
    var totalMutations: Long = 0L
        private set

    fun addRule(rule: AndroidRewriteRule) {
        rules.add(rule)
    }

    fun matchRule(domain: String, path: String): AndroidRewriteRule? {
        val domLower = domain.lowercase()
        return rules.firstOrNull { rule ->
            if (!rule.isActive) return@firstOrNull false
            val domMatch = when {
                rule.domainPattern == "*" -> true
                rule.domainPattern.startsWith("*.") -> domLower.endsWith(rule.domainPattern.removePrefix("*."))
                else -> domLower == rule.domainPattern.lowercase()
            }
            domMatch && path.startsWith(rule.pathPrefix)
        }
    }

    fun rewriteRequest(domain: String, path: String, headers: MutableMap<String, String>): Pair<String, AndroidRewriteAction?> {
        val rule = matchRule(domain, path) ?: return Pair(path, null)
        totalMutations++

        var newPath = path
        when (val act = rule.action) {
            is AndroidRewriteAction.RedirectUrl -> newPath = act.newUrl
            is AndroidRewriteAction.SetHeader -> headers[act.name] = act.value
            is AndroidRewriteAction.RemoveHeader -> headers.remove(act.name)
            else -> {}
        }
        return Pair(newPath, rule.action)
    }

    fun rewriteResponseBody(domain: String, path: String, body: ByteArray): ByteArray {
        val rule = matchRule(domain, path) ?: return body
        if (rule.action is AndroidRewriteAction.ReplaceBody) {
            val str = String(body, Charsets.UTF_8)
            if (str.contains(rule.action.pattern)) {
                totalMutations++
                return str.replace(rule.action.pattern, rule.action.replacement).toByteArray(Charsets.UTF_8)
            }
        }
        return body
    }
}
