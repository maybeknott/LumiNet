// Copyright 2024-2026 LumiNet Authors. All Rights Reserved.
package com.luminet.android.tunnel

data class RelayHop(
    val hopIndex: Int,
    val endpoint: String,
    val publicKey: String
)

class MultihopRelayChain(
    val entryHop: RelayHop,
    val exitHop: RelayHop,
    val quantumResistantPsk: ByteArray
) {
    fun getNestedAllowedIps(): Pair<String, String> {
        return Pair("10.64.0.1/32", "0.0.0.0/0, ::/0")
    }
}
