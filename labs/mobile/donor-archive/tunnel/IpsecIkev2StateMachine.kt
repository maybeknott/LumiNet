package com.luminet.android.tunnel

import java.nio.ByteBuffer
import java.security.SecureRandom

enum class AndroidIkeState {
    INIT,
    SA_INIT_SENT,
    SA_INIT_RECV,
    AUTH_SENT,
    ESTABLISHED,
    CLOSED
}

class IpsecIkev2StateMachine(val sharedSecret: ByteArray) {
    var state: AndroidIkeState = AndroidIkeState.INIT
        private set

    val initiatorSpi: Long
    var responderSpi: Long = 0
        private set
    private var messageId: Int = 0

    init {
        require(sharedSecret.size >= 16) { "Shared secret must be at least 16 bytes" }
        initiatorSpi = SecureRandom().nextLong()
    }

    fun buildSaInitRequest(nonce: ByteArray): ByteArray {
        check(state == AndroidIkeState.INIT) { "Cannot send SA_INIT from non-INIT state" }

        val totalLen = 28 + nonce.size
        val buf = ByteBuffer.allocate(totalLen)
        buf.putLong(initiatorSpi)
        buf.putLong(0L) // responder SPI is 0 in request
        buf.put(33.toByte()) // Next Payload: SA
        buf.put(0x20.toByte()) // IKEv2 version
        buf.put(34.toByte()) // Exchange Type: IKE_SA_INIT
        buf.put(0x08.toByte()) // Flags: Initiator
        buf.putInt(messageId++)
        buf.putInt(totalLen)
        buf.put(nonce)

        state = AndroidIkeState.SA_INIT_SENT
        return buf.array()
    }

    fun processSaInitResponse(resp: ByteArray): Boolean {
        if (state != AndroidIkeState.SA_INIT_SENT || resp.size < 28) return false

        val buf = ByteBuffer.wrap(resp)
        val initSpi = buf.getLong()
        if (initSpi != initiatorSpi) return false

        val respSpi = buf.getLong()
        if (respSpi == 0L) return false

        responderSpi = respSpi
        state = AndroidIkeState.SA_INIT_RECV
        return true
    }

    fun transitionToAuth(): Boolean {
        if (state != AndroidIkeState.SA_INIT_RECV) return false
        state = AndroidIkeState.AUTH_SENT
        return true
    }

    fun finalizeEstablished(): Boolean {
        if (state != AndroidIkeState.AUTH_SENT) return false
        state = AndroidIkeState.ESTABLISHED
        return true
    }

    fun close() {
        state = AndroidIkeState.CLOSED
    }
}
