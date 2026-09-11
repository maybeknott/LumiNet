package com.luminet.android.tunnel

enum class SocketState {
    Active, Standby, Degraded, Dead
}

data class ManagedSocket(
    val id: String,
    val endpoint: String,
    var state: SocketState,
    var failures: Int = 0,
    var lastRttMs: Long = 0
)

class SocketPoolSupervisor {
    private val sockets = mutableMapOf<String, ManagedSocket>()
    var activeSocketId: String? = null
        private set

    fun registerSocket(id: String, endpoint: String) {
        val isFirst = sockets.isEmpty()
        val state = if (isFirst) SocketState.Active else SocketState.Standby
        if (isFirst) activeSocketId = id
        sockets[id] = ManagedSocket(id, endpoint, state)
    }

    fun recordHeartbeat(id: String, rttMs: Long, success: Boolean) {
        val sock = sockets[id] ?: return
        sock.lastRttMs = rttMs
        if (success) {
            sock.failures = 0
            if (sock.state == SocketState.Degraded) sock.state = SocketState.Standby
        } else {
            sock.failures++
            sock.state = if (sock.failures >= 3) SocketState.Dead else SocketState.Degraded
        }

        if (activeSocketId == id && !success) {
            electNewActive()
        }
    }

    private fun electNewActive() {
        val candidate = sockets.values
            .filter { it.state == SocketState.Standby }
            .minByOrNull { it.lastRttMs }

        candidate?.let {
            sockets[activeSocketId]?.state = SocketState.Standby
            it.state = SocketState.Active
            activeSocketId = it.id
        }
    }

    fun getActiveSocket(): ManagedSocket? = activeSocketId?.let { sockets[it] }
}
