package com.luminet.android.scanner

import java.io.ByteArrayOutputStream
import java.io.DataOutputStream
import java.nio.charset.StandardCharsets

/**
 * Cloudflare Edge Trace Diagnostic Information.
 * Extracted from http://connectivity.cloudflareclient.com/cdn-cgi/trace
 */
data class CloudflareTraceInfo(
    val colo: String? = null,
    val loc: String? = null,
    val ip: String? = null,
    val warp: String? = null,
    val visitScheme: String? = null,
    val isWarpOk: Boolean = false
)

/**
 * Validation stage specification in an attempt ladder.
 */
data class AttemptStage(
    val attemptIndex: Int,
    val label: String,
    val budgetSec: Long,
    val endpoint: String
)

/**
 * SOCKS5 Packet Builder & Verification Utilities.
 * Handles wire-level framing for protocol handshake and connection stages.
 */
object SocksPacketBuilder {
    const val SOCKS_VERSION: Byte = 0x05
    const val CMD_CONNECT: Byte = 0x01
    const val ATYP_IPV4: Byte = 0x01
    const val ATYP_DOMAIN: Byte = 0x03
    const val ATYP_IPV6: Byte = 0x04

    fun buildGreeting(authMethods: ByteArray = byteArrayOf(0x00)): ByteArray {
        val out = ByteArrayOutputStream()
        out.write(SOCKS_VERSION.toInt())
        out.write(authMethods.size)
        out.write(authMethods)
        return out.toByteArray()
    }

    fun verifyGreetingReply(reply: ByteArray): Byte {
        if (reply.size < 2) {
            throw IllegalArgumentException("SOCKS greeting reply too short (${reply.size} < 2)")
        }
        if (reply[0] != SOCKS_VERSION) {
            throw IllegalArgumentException("Invalid SOCKS version in greeting reply: ${reply[0]}")
        }
        if (reply[1] == 0xFF.toByte()) {
            throw IllegalStateException("SOCKS server rejected authentication methods")
        }
        return reply[1]
    }

    fun buildConnectIpv4(ipBytes: ByteArray, port: Int): ByteArray {
        require(ipBytes.size == 4) { "IPv4 address must be exactly 4 bytes" }
        val out = ByteArrayOutputStream()
        val data = DataOutputStream(out)
        data.writeByte(SOCKS_VERSION.toInt())
        data.writeByte(CMD_CONNECT.toInt())
        data.writeByte(0x00) // Reserved
        data.writeByte(ATYP_IPV4.toInt())
        data.write(ipBytes)
        data.writeShort(port and 0xFFFF)
        data.flush()
        return out.toByteArray()
    }

    fun buildConnectDomain(domain: String, port: Int): ByteArray {
        val domainBytes = domain.toByteArray(StandardCharsets.US_ASCII)
        require(domainBytes.size <= 255) { "Domain name too long for SOCKS5: ${domain.length}" }
        val out = ByteArrayOutputStream()
        val data = DataOutputStream(out)
        data.writeByte(SOCKS_VERSION.toInt())
        data.writeByte(CMD_CONNECT.toInt())
        data.writeByte(0x00) // Reserved
        data.writeByte(ATYP_DOMAIN.toInt())
        data.writeByte(domainBytes.size)
        data.write(domainBytes)
        data.writeShort(port and 0xFFFF)
        data.flush()
        return out.toByteArray()
    }

    fun verifyConnectReply(reply: ByteArray) {
        if (reply.size < 4) {
            throw IllegalArgumentException("SOCKS connect reply too short (${reply.size} < 4)")
        }
        if (reply[0] != SOCKS_VERSION) {
            throw IllegalArgumentException("Invalid SOCKS version in connect reply: ${reply[0]}")
        }
        val rep = reply[1]
        if (rep != 0x00.toByte()) {
            val errStr = when (rep) {
                0x01.toByte() -> "general SOCKS server failure"
                0x02.toByte() -> "connection not allowed by ruleset"
                0x03.toByte() -> "network unreachable"
                0x04.toByte() -> "host unreachable"
                0x05.toByte() -> "connection refused"
                0x06.toByte() -> "TTL expired"
                0x07.toByte() -> "command not supported"
                0x08.toByte() -> "address type not supported"
                else -> "unknown error code 0x${rep.toString(16)}"
            }
            throw IllegalStateException("SOCKS connect error: $errStr")
        }
    }

    fun parseTraceBody(body: String): CloudflareTraceInfo {
        var colo: String? = null
        var loc: String? = null
        var ip: String? = null
        var warp: String? = null
        var visitScheme: String? = null

        body.lineSequence().forEach { line ->
            val trimmed = line.trim()
            val eqIdx = trimmed.indexOf('=')
            if (eqIdx > 0) {
                val key = trimmed.substring(0, eqIdx).trim()
                val value = trimmed.substring(eqIdx + 1).trim()
                when (key) {
                    "colo" -> colo = value
                    "loc" -> loc = value
                    "ip" -> ip = value
                    "warp" -> warp = value
                    "visit_scheme" -> visitScheme = value
                }
            }
        }

        val isWarpOk = (warp == "on" || warp == "plus")
        return CloudflareTraceInfo(
            colo = colo,
            loc = loc,
            ip = ip,
            warp = warp,
            visitScheme = visitScheme,
            isWarpOk = isWarpOk
        )
    }
}

/**
 * Adaptive timeout budget ladder orchestrator for multi-attempt SOCKS validation.
 */
object AttemptLadder {
    fun calculateValidationBudget(mode: String): Long {
        return when (mode.trim().lowercase()) {
            "turbo" -> 105L
            "thorough" -> 360L
            "stealth" -> 240L
            else -> 180L
        }
    }

    fun buildAttempts(
        mode: String,
        endpoint: String,
        fastFirstConnect: Boolean,
        isPsiphon: Boolean
    ): List<AttemptStage> {
        val budget = calculateValidationBudget(mode)
        if (isPsiphon) {
            return listOf(
                AttemptStage(
                    attemptIndex = 0,
                    label = "configured",
                    budgetSec = budget,
                    endpoint = endpoint
                )
            )
        }

        val list = mutableListOf<AttemptStage>()
        var idx = 0
        if (fastFirstConnect) {
            list.add(
                AttemptStage(
                    attemptIndex = idx++,
                    label = "fast",
                    budgetSec = 30L,
                    endpoint = endpoint
                )
            )
        }
        list.add(
            AttemptStage(
                attemptIndex = idx,
                label = "configured",
                budgetSec = budget,
                endpoint = endpoint
            )
        )
        return list
    }
}
