// Copyright 2024-2026 LumiNet Authors. All Rights Reserved.
package com.luminet.android.tunnel

data class ProtocolConfigPreset(
    val listenPort: Int,
    val serverUuid: String,
    val sniDest: String,
    val transport: String = "tcp-reality"
)

object MultiprotocolConfigSynthesizer {
    fun generateSingboxInbound(preset: ProtocolConfigPreset): String {
        return """{"type":"vless","tag":"in-\${preset.transport}","listen_port":\${preset.listenPort},"users":[{"uuid":"\${preset.serverUuid}"}],"tls":{"enabled":true,"server_name":"\${preset.sniDest}"}}"""
    }
}
