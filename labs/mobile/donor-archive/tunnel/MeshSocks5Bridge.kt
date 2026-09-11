package com.luminet.android.tunnel

import java.io.ByteArrayOutputStream
import java.nio.ByteBuffer
import java.util.concurrent.ConcurrentHashMap

enum class AndroidSocks5Disposition {
    DIRECT,
    MESH_EXIT,
    BLOCKED
}

data class AndroidMeshExitNode(
    val nodeId: String,
    val virtualIp: String,
    val active: Boolean
)

class MeshSocks5Bridge(val listenPort: Int) {
    private var exitNode: AndroidMeshExitNode? = null
    private val credentials = ConcurrentHashMap<String, String>()

    fun setExitNode(node: AndroidMeshExitNode) {
        exitNode = node
    }

    fun addUser(user: String, pass: String) {
        credentials[user] = pass
    }

    fun authenticate(user: String, pass: String): Boolean {
        if (credentials.isEmpty()) return true
        return credentials[user] == pass
    }

    fun evaluateRoute(host: String, port: Int): Pair<AndroidSocks5Disposition, String?> {
        if (port <= 0 || port > 65535) return Pair(AndroidSocks5Disposition.BLOCKED, null)
        if (host == "localhost" || host == "127.0.0.1") return Pair(AndroidSocks5Disposition.DIRECT, null)

        val exit = exitNode
        if (exit != null && exit.active) {
            return Pair(AndroidSocks5Disposition.MESH_EXIT, exit.virtualIp)
        }
        return Pair(AndroidSocks5Disposition.DIRECT, null)
    }

    fun parseGreeting(data: ByteArray): Byte {
        if (data.size < 2 || data[0] != 0x05.toByte()) return 0xFF.toByte()
        val nmethods = data[1].toInt() and 0xFF
        if (data.size < 2 + nmethods) return 0xFF.toByte()

        val methods = data.copyOfRange(2, 2 + nmethods)
        return if (credentials.isEmpty()) {
            if (methods.contains(0x00.toByte())) 0x00.toByte() else 0xFF.toByte()
        } else {
            if (methods.contains(0x02.toByte())) 0x02.toByte() else 0xFF.toByte()
        }
    }

    fun craftReply(repCode: Byte, bindIp: String, bindPort: Int): ByteArray {
        val out = ByteArrayOutputStream()
        out.write(0x05)
        out.write(repCode.toInt())
        out.write(0x00) // Reserved
        out.write(0x01) // IPv4

        val ipParts = bindIp.split(".").map { it.toInt().toByte() }
        out.write(ipParts.toByteArray())

        val portBuf = ByteBuffer.allocate(2)
        portBuf.putShort(bindPort.toShort())
        out.write(portBuf.array())

        return out.toByteArray()
    }
}
