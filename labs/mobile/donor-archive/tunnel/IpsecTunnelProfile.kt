// Copyright 2024-2026 LumiNet Authors. All Rights Reserved.
package com.luminet.android.tunnel

import java.security.SecureRandom

data class Ikev2Proposal(
    val encryption: String = "aes256gcm128",
    val integrity: String = "sha256",
    val dhGroup: String = "modp2048",
    val pfsGroup: String = "modp2048",
    val lifetimeSec: Int = 3600
)

data class IpsecProfile(
    val serverEndpoint: String,
    val serverPort: Int = 500,
    val pskHex: String,
    val leftId: String,
    val rightId: String,
    val proposal: Ikev2Proposal = Ikev2Proposal(),
    val natKeepaliveSec: Int = 20
) {
    fun generateSwanctlConf(): String {
        return """
connections {
  lumi-$leftId {
    remote_addrs = $serverEndpoint
    vips = 0.0.0.0,::
    local {
      auth = psk
      id = $leftId
    }
    remote {
      auth = psk
      id = $rightId
    }
    children {
      net {
        remote_ts = 0.0.0.0/0,::/0
        esp_proposals = \${proposal.encryption}-\${proposal.integrity}-\${proposal.pfsGroup}
        start_action = start
      }
    }
  }
}
""".trimIndent()
    }

    companion object {
        fun create(server: String, leftId: String, rightId: String): IpsecProfile {
            val psk = ByteArray(32)
            SecureRandom().nextBytes(psk)
            val pskHex = psk.joinToString("") { "%02x".format(it) }
            return IpsecProfile(
                serverEndpoint = server,
                pskHex = pskHex,
                leftId = leftId,
                rightId = rightId
            )
        }
    }
}
