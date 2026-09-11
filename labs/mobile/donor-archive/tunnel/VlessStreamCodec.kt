package com.luminet.android.tunnel

import java.net.Inet4Address
import java.net.Inet6Address
import java.net.InetAddress
import java.nio.ByteBuffer
import java.nio.charset.StandardCharsets
import java.util.UUID

/**
 * VLESS Command types (RFC / Xray spec).
 */
enum class VlessCommand(val value: Byte) {
    TCP(1),
    UDP(2),
    MUX(3);

    companion object {
        fun fromByte(b: Byte): VlessCommand? = entries.find { it.value == b }
    }
}

/**
 * Target destination addresses supported by VLESS.
 */
sealed class VlessAddress {
    data class IPv4(val address: Inet4Address) : VlessAddress()
    data class Domain(val domain: String) : VlessAddress()
    data class IPv6(val address: Inet6Address) : VlessAddress()
}

/**
 * VLESS request header representation.
 */
data class VlessRequestHeader(
    val version: Byte = 0,
    val uuid: ByteArray,
    val command: VlessCommand,
    val port: Int,
    val address: VlessAddress,
    val addons: ByteArray = ByteArray(0)
) {
    init {
        require(uuid.size == 16) { "UUID must be exactly 16 bytes" }
    }

    fun serialize(): ByteArray {
        val addrBytes = when (val a = address) {
            is VlessAddress.IPv4 -> byteArrayOf(0x01) + a.address.address
            is VlessAddress.Domain -> {
                val dBytes = a.domain.toByteArray(StandardCharsets.UTF_8)
                byteArrayOf(0x02, dBytes.size.toByte()) + dBytes
            }
            is VlessAddress.IPv6 -> byteArrayOf(0x03) + a.address.address
        }

        val totalSize = 1 + 16 + 1 + addons.size + 1 + 2 + addrBytes.size
        val bb = ByteBuffer.allocate(totalSize)
        bb.put(version)
        bb.put(uuid)
        bb.put(addons.size.toByte())
        if (addons.isNotEmpty()) {
            bb.put(addons)
        }
        bb.put(command.value)
        bb.putShort(port.toShort())
        bb.put(addrBytes)
        return bb.array()
    }

    companion object {
        fun deserialize(bytes: ByteArray): Pair<VlessRequestHeader, Int> {
            require(bytes.size >= 19) { "Buffer too short for VLESS request header" }
            val bb = ByteBuffer.wrap(bytes)
            val version = bb.get()
            val uuid = ByteArray(16)
            bb.get(uuid)
            val addonsLen = bb.get().toInt() and 0xFF
            require(bytes.size >= 18 + addonsLen + 4) { "Buffer too short for addons/command" }

            val addons = ByteArray(addonsLen)
            if (addonsLen > 0) {
                bb.get(addons)
            }

            val cmdByte = bb.get()
            val command = VlessCommand.fromByte(cmdByte)
                ?: throw IllegalArgumentException("Invalid VLESS command: ")

            val port = bb.short.toInt() and 0xFFFF
            val addrType = bb.get().toInt() and 0xFF

            val address = when (addrType) {
                0x01 -> {
                    require(bb.remaining() >= 4) { "Buffer too short for IPv4" }
                    val ipBytes = ByteArray(4)
                    bb.get(ipBytes)
                    VlessAddress.IPv4(InetAddress.getByAddress(ipBytes) as Inet4Address)
                }
                0x02 -> {
                    require(bb.remaining() >= 1) { "Buffer too short for domain length" }
                    val dLen = bb.get().toInt() and 0xFF
                    require(bb.remaining() >= dLen) { "Buffer too short for domain string" }
                    val dBytes = ByteArray(dLen)
                    bb.get(dBytes)
                    VlessAddress.Domain(String(dBytes, StandardCharsets.UTF_8))
                }
                0x03 -> {
                    require(bb.remaining() >= 16) { "Buffer too short for IPv6" }
                    val ipBytes = ByteArray(16)
                    bb.get(ipBytes)
                    VlessAddress.IPv6(InetAddress.getByAddress(ipBytes) as Inet6Address)
                }
                else -> throw IllegalArgumentException("Unsupported address type: ")
            }

            val consumed = bb.position()
            return Pair(
                VlessRequestHeader(
                    version = version,
                    uuid = uuid,
                    command = command,
                    port = port,
                    address = address,
                    addons = addons
                ),
                consumed
            )
        }
    }
}

/**
 * VLESS server response header.
 */
data class VlessResponseHeader(
    val version: Byte = 0,
    val addons: ByteArray = ByteArray(0)
) {
    fun serialize(): ByteArray {
        val bb = ByteBuffer.allocate(2 + addons.size)
        bb.put(version)
        bb.put(addons.size.toByte())
        if (addons.isNotEmpty()) {
            bb.put(addons)
        }
        return bb.array()
    }

    companion object {
        fun deserialize(bytes: ByteArray): Pair<VlessResponseHeader, Int> {
            require(bytes.size >= 2) { "Buffer too short for VLESS response header" }
            val version = bytes[0]
            val addonsLen = bytes[1].toInt() and 0xFF
            require(bytes.size >= 2 + addonsLen) { "Buffer too short for response addons" }

            val addons = ByteArray(addonsLen)
            if (addonsLen > 0) {
                System.arraycopy(bytes, 2, addons, 0, addonsLen)
            }
            return Pair(VlessResponseHeader(version, addons), 2 + addonsLen)
        }
    }
}
