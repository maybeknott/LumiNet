package com.luminet.android.tunnel

data class UnifiedOutboundDefinition(
    val tag: String,
    val protocol: String,
    val server: String,
    val serverPort: Int,
    val uuid: String,
    val tlsSni: String,
    val transportType: String,
    val wsPath: String
)

class MultiFormatCompiler {
    fun compileSingBox(def: UnifiedOutboundDefinition): String {
        return "{\"type\":\"${def.protocol}\",\"tag\":\"${def.tag}\",\"server\":\"${def.server}\",\"server_port\":${def.serverPort},\"uuid\":\"${def.uuid}\",\"tls\":{\"enabled\":true,\"server_name\":\"${def.tlsSni}\"},\"transport\":{\"type\":\"${def.transportType}\",\"path\":\"${def.wsPath}\"}}"
    }

    fun compileXray(def: UnifiedOutboundDefinition): String {
        return "{\"protocol\":\"${def.protocol}\",\"tag\":\"${def.tag}\",\"settings\":{\"vnext\":[{\"address\":\"${def.server}\",\"port\":${def.serverPort},\"users\":[{\"id\":\"${def.uuid}\"}]}]},\"streamSettings\":{\"network\":\"${def.transportType}\",\"security\":\"tls\",\"tlsSettings\":{\"serverName\":\"${def.tlsSni}\"},\"wsSettings\":{\"path\":\"${def.wsPath}\"}}}"
    }

    fun compileClash(def: UnifiedOutboundDefinition): String {
        return "- name: \"${def.tag}\"\n  type: ${def.protocol}\n  server: ${def.server}\n  port: ${def.serverPort}\n  uuid: ${def.uuid}\n  tls: true\n  servername: ${def.tlsSni}\n  network: ${def.transportType}\n  ws-opts:\n    path: ${def.wsPath}"
    }
}
