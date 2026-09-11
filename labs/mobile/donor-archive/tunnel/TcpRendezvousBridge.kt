package com.luminet.android.tunnel

data class RendezvousSession(
    val token: String,
    val initiator: String,
    var responder: String? = null,
    var isConnected: Boolean = false
)

class TcpRendezvousBridge {
    private val sessions = mutableMapOf<String, RendezvousSession>()

    fun register(initiator: String): String {
        val token = "rdv-${System.currentTimeMillis()}-${(1000..9999).random()}"
        sessions[token] = RendezvousSession(token, initiator)
        return token
    }

    fun connect(token: String, responder: String): RendezvousSession {
        val session = sessions[token] ?: throw IllegalArgumentException("invalid token")
        if (session.isConnected) throw IllegalStateException("already connected")
        session.responder = responder
        session.isConnected = true
        return session
    }

    fun get(token: String): RendezvousSession? = sessions[token]
}
