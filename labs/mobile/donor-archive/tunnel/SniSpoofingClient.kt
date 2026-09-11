package com.luminet.android.tunnel

/**
 * SNI Spoofing and Out-Of-Window Decoy Injector for Android clients.
 * Originates from SNI-Spoofing-Go-main and adapted for LumiNet unified network plane.
 */
object SniSpoofingClient {

    const val CLIENT_HELLO_SIZE = 517
    const val MAX_SNI_BYTES = 219

    /**
     * Calculates out-of-window sequence number for decoy injection:
     * Formula: (ISN + 1 - payload_len) & 0xFFFFFFFF
     */
    fun computeOutOfWindowSeq(isn: Long, payloadLen: Int): Long {
        return (isn + 1L - payloadLen.toLong()) and 0xFFFFFFFFL
    }

    /**
     * Checks if a target decoy SNI is a valid ASCII hostname.
     */
    fun isValidSni(sni: String): Boolean {
        if (sni.isEmpty() || sni.length > MAX_SNI_BYTES || sni.startsWith(".") || sni.endsWith(".")) {
            return false
        }
        val labels = sni.split(".")
        for (label in labels) {
            if (label.isEmpty() || label.length > 63 || label.startsWith("-") || label.endsWith("-")) {
                return false
            }
            for (c in label) {
                if (!c.isLetterOrDigit() && c != '-') {
                    return false
                }
            }
        }
        return true
    }

    enum class HandshakePhase {
        INITIAL,
        SYN_SENT,
        SYN_ACK_RECEIVED,
        HANDSHAKE_COMPLETE,
        DECOY_INJECTED,
        DECOY_ACKNOWLEDGED,
        TERMINATED
    }

    data class DecoyPlan(
        val scheduleDecoy: Boolean,
        val decoySeq: Long = 0L,
        val newIdent: Int = 0
    )

    /**
     * TCP 3-way handshake state machine tracking client/server sequences.
     */
    class TcpDesyncTracker(
        val srcIp: String,
        val dstIp: String,
        val srcPort: Int,
        val dstPort: Int
    ) {
        var synSeq: Long = -1L
            private set
        var synAckSeq: Long = -1L
            private set
        var phase: HandshakePhase = HandshakePhase.INITIAL
            private set

        @Synchronized
        fun processOutbound(
            seq: Long,
            ack: Long,
            isSyn: Boolean,
            isAck: Boolean,
            currIdent: Int,
            fakeLen: Int
        ): DecoyPlan {
            if (isSyn && !isAck) {
                if (ack != 0L) {
                    phase = HandshakePhase.TERMINATED
                    throw IllegalArgumentException("Outbound SYN ack is not zero")
                }
                synSeq = seq
                phase = HandshakePhase.SYN_SENT
                return DecoyPlan(scheduleDecoy = false)
            }

            if (isAck && !isSyn && phase == HandshakePhase.SYN_ACK_RECEIVED) {
                val expectedSeq = (synSeq + 1L) and 0xFFFFFFFFL
                val expectedAck = (synAckSeq + 1L) and 0xFFFFFFFFL
                if (seq != expectedSeq || ack != expectedAck) {
                    phase = HandshakePhase.TERMINATED
                    throw IllegalStateException("Handshake ACK sequence mismatch")
                }

                val decoySeq = computeOutOfWindowSeq(synSeq, fakeLen)
                val newIdent = (currIdent + 1) and 0xFFFF
                phase = HandshakePhase.DECOY_INJECTED
                return DecoyPlan(scheduleDecoy = true, decoySeq = decoySeq, newIdent = newIdent)
            }

            return DecoyPlan(scheduleDecoy = false)
        }

        @Synchronized
        fun processInbound(
            seq: Long,
            ack: Long,
            isSyn: Boolean,
            isAck: Boolean
        ): Boolean {
            if (isSyn && isAck) {
                val expectedAck = (synSeq + 1L) and 0xFFFFFFFFL
                if (ack != expectedAck) {
                    phase = HandshakePhase.TERMINATED
                    throw IllegalStateException("SYN-ACK ack mismatch")
                }
                synAckSeq = seq
                phase = HandshakePhase.SYN_ACK_RECEIVED
                return false
            }

            if (isAck && !isSyn && phase == HandshakePhase.DECOY_INJECTED) {
                val expectedSeq = (synAckSeq + 1L) and 0xFFFFFFFFL
                val expectedAck = (synSeq + 1L) and 0xFFFFFFFFL
                if (seq == expectedSeq && ack == expectedAck) {
                    phase = HandshakePhase.DECOY_ACKNOWLEDGED
                    return true
                }
            }

            return false
        }
    }

    val TLS_CHANGE_CIPHER = byteArrayOf(0x14, 0x03, 0x03, 0x00, 0x01, 0x01)
    val TLS_APP_DATA_HEADER = byteArrayOf(0x17, 0x03, 0x03)

    /**
     * Synthesizes TLS ChangeCipherSpec + ApplicationData envelope for client response.
     */
    fun buildClientResponseWith(appData: ByteArray): ByteArray {
        val out = ByteArray(11 + appData.size)
        System.arraycopy(TLS_CHANGE_CIPHER, 0, out, 0, 6)
        System.arraycopy(TLS_APP_DATA_HEADER, 0, out, 6, 3)
        out[9] = (appData.size ushr 8).toByte()
        out[10] = appData.size.toByte()
        System.arraycopy(appData, 0, out, 11, appData.size)
        return out
    }

    /**
     * Parses client response envelope and extracts raw application data.
     */
    fun parseClientResponse(data: ByteArray): ByteArray {
        if (data.size < 11) {
            throw IllegalArgumentException("Client response too short")
        }
        val len = ((data[9].toInt() and 0xFF) shl 8) or (data[10].toInt() and 0xFF)
        if (data.size < 11 + len) {
            throw IllegalArgumentException("Truncated client response")
        }
        val appData = ByteArray(len)
        System.arraycopy(data, 11, appData, 0, len)
        return appData
    }
}

