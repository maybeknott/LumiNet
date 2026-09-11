package com.luminet.android.tunnel

data class SessionTicket(
    val serverName: String,
    val ticketBytes: ByteArray,
    val alpn: String,
    val expiresAtUnix: Long
)

class ZeroRttSessionCache {
    private val tickets = mutableMapOf<String, SessionTicket>()
    private val consumedNonces = mutableSetOf<String>()

    fun storeTicket(serverName: String, ticket: ByteArray, alpn: String, nowUnix: Long, ttlSecs: Long) {
        val key = serverName.lowercase()
        tickets[key] = SessionTicket(serverName, ticket.copyOf(), alpn, nowUnix + ttlSecs)
    }

    fun getValidTicket(serverName: String, nowUnix: Long): SessionTicket? {
        val key = serverName.lowercase()
        val t = tickets[key] ?: return null
        if (t.expiresAtUnix > nowUnix) {
            return t
        }
        tickets.remove(key)
        return null
    }

    fun checkAndConsumeNonce(nonce: ByteArray): Boolean {
        val key = nonce.joinToString("") { "%02x".format(it) }
        return consumedNonces.add(key)
    }
}
