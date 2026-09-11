package com.luminet.android.tunnel

data class DnsWizardConfig(
    val profileName: String,
    val dnsServer: String,
    val rootDomain: String,
    val obfuscationKey: String,
    val compression: Boolean = true,
    val port: Int = 53
)

data class WizardProfileResult(
    val id: String,
    val uri: String,
    val isReady: Boolean
)

class DnsWizardConfigGenerator {
    fun generate(config: DnsWizardConfig): WizardProfileResult {
        require(config.profileName.isNotBlank()) { "profileName cannot be empty" }
        require(config.dnsServer.isNotBlank()) { "dnsServer cannot be empty" }
        require(config.rootDomain.isNotBlank()) { "rootDomain cannot be empty" }

        val port = if (config.port in 1..65535) config.port else 53
        val uri = "dnsvpn://${config.obfuscationKey}@${config.dnsServer}:$port?domain=${config.rootDomain}&comp=${config.compression}"
        val id = "dns-wiz-${config.profileName.lowercase().replace(" ", "-")}"

        return WizardProfileResult(
            id = id,
            uri = uri,
            isReady = true
        )
    }
}
