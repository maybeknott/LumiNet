package com.luminet.android.tunnel

data class AndroidReverseSession(
    val sessionId: Long,
    val remoteAddr: String,
    val targetAddr: String,
    var bytesIn: Long = 0,
    var bytesOut: Long = 0,
    var isConnected: Boolean = true
)

class ReverseTunnelRelay(private val maxSessions: Int = 100) {
    private val sessions = mutableMapOf<Long, AndroidReverseSession>()
    private var nextId = 1L

    @Synchronized
    fun openSession(remoteAddr: String, targetAddr: String): Long? {
        if (sessions.size >= maxSessions) return null
        val id = nextId++
        sessions[id] = AndroidReverseSession(id, remoteAddr, targetAddr)
        return id
    }

    @Synchronized
    fun recordTraffic(sessionId: Long, inBytes: Long, outBytes: Long): Boolean {
        val s = sessions[sessionId] ?: return false
        if (!s.isConnected) return false
        s.bytesIn += inBytes
        s.bytesOut += outBytes
        return true
    }

    @Synchronized
    fun closeSession(sessionId: Long): Boolean {
        val s = sessions.remove(sessionId) ?: return false
        s.isConnected = false
        return true
    }

    fun activeSessions(): Int = sessions.size
}
