// Copyright 2024-2026 LumiNet Authors. All Rights Reserved.
package com.luminet.android.tunnel

data class SysctlCheck(
    val key: String,
    val expected: String,
    val critical: Boolean
)

class KernelHardeningAuditor {
    private val checks = listOf(
        SysctlCheck("net.ipv4.ip_forward", "1", true),
        SysctlCheck("net.ipv4.conf.all.rp_filter", "1", true),
        SysctlCheck("net.ipv4.conf.default.rp_filter", "1", true),
        SysctlCheck("net.ipv4.conf.all.accept_source_route", "0", true),
        SysctlCheck("net.ipv4.tcp_syncookies", "1", true)
    )

    fun audit(current: Map<String, String>): Double {
        var compliant = 0
        for (check in checks) {
            if (current[check.key] == check.expected) {
                compliant++
            }
        }
        return (compliant.toDouble() / checks.size.toDouble()) * 100.0
    }
}
