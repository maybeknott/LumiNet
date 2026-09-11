package com.luminet.android.tunnel

class AutonomousRoutingCoordinator(val defaultProxyNode: String = "US-Primary") {
    val pac = PacScriptCompiler(defaultProxyNode)
    val autoProxy = AutoProxyRulesetMatcher()
    val singbox = SingboxRulesetCompiler()

    fun evaluate(target: String): String {
        val apVerdict = autoProxy.match(target)
        if (apVerdict != null) {
            return if (apVerdict == "DIRECT") "DIRECT" else "PROXY $defaultProxyNode"
        }

        val sbOutbound = singbox.matchDomain(target)
        if (sbOutbound != null) {
            return if (sbOutbound == "direct") "DIRECT" else "PROXY $sbOutbound"
        }

        return pac.evaluateDomain(target)
    }
}
