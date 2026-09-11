package com.luminet.android.tunnel

/**
 * Connection identifier 4-tuple for TCP tracking.
 */
data class ConnId(
    val srcIp: String,
    val srcPort: Int,
    val dstIp: String,
    val dstPort: Int
)

/**
 * Handshake progression states for TCP 3-way handshake tracking.
 */
enum class HandshakePhase {
    INITIAL,
    SYN_SENT,
    SYN_ACK_RECEIVED,
    HANDSHAKE_COMPLETE,
    DECOY_INJECTED,
    DECOY_ACKNOWLEDGED,
    TERMINATED
}

/**
 * Action instructed after evaluating an outbound packet.
 */
data class OutboundAction(
    val scheduleDecoy: Boolean = false,
    val decoySeq: Long = 0L,
    val newIdent: Int = 0
)

/**
 * Action instructed after evaluating an inbound packet.
 */
data class InboundAction(
    val decoyAcknowledged: Boolean = false
)

/**
 * Tracks TCP connection state to time out-of-window DPI decoy injection precisely.
 * Originates from Project 62 (sniSpoofingAdvanced).
 */
class TcpDesyncTracker(
    val id: ConnId
) {
    var synSeq: Long = -1L
        private set
    var synAckSeq: Long = -1L
        private set
    var phase: HandshakePhase = HandshakePhase.INITIAL
        private set
    var fakeSent: Boolean = false
        private set
    var schFakeSent: Boolean = false
        private set

    private val lock = Any()

    /**
     * Evaluates an outbound packet from client to remote server.
     */
    fun processOutbound(
        seq: Long,
        ack: Long,
        isSyn: Boolean,
        isAck: Boolean,
        isRst: Boolean,
        isFin: Boolean,
        payloadLen: Int,
        currIdent: Int,
        fakeLen: Int
    ): OutboundAction {
        synchronized(lock) {
            if (phase == HandshakePhase.DECOY_INJECTED || phase == HandshakePhase.DECOY_ACKNOWLEDGED) {
                return OutboundAction()
            }

            // 1. Outbound SYN: SYN=1, ACK=0, payload=0
            if (isSyn && !isAck && !isRst && !isFin && payloadLen == 0) {
                if (ack != 0L) {
                    phase = HandshakePhase.TERMINATED
                    throw IllegalArgumentException("outbound SYN ack number is not zero: ")
                }
                if (synSeq != -1L && synSeq != seq) {
                    phase = HandshakePhase.TERMINATED
                    throw IllegalStateException("outbound SYN seq mismatch:  != ")
                }
                synSeq = seq
                phase = HandshakePhase.SYN_SENT
                return OutboundAction()
            }

            // 2. Outbound ACK completing handshake: SYN=0, ACK=1, payload=0
            if (isAck && !isSyn && !isRst && !isFin && payloadLen == 0) {
                val expectedSeq = ((synSeq + 1) and 0xFFFFFFFFL)
                if (synSeq == -1L || seq != expectedSeq) {
                    phase = HandshakePhase.TERMINATED
                    throw IllegalStateException("outbound ACK seq mismatch:  != ")
                }
                val expectedAck = ((synAckSeq + 1) and 0xFFFFFFFFL)
                if (synAckSeq == -1L || ack != expectedAck) {
                    phase = HandshakePhase.TERMINATED
                    throw IllegalStateException("outbound ACK ack mismatch:  != ")
                }

                schFakeSent = true
                phase = HandshakePhase.HANDSHAKE_COMPLETE

                // Out-of-window sequence formula: (SynSeq + 1 - fakeLen) & 0xFFFFFFFF
                val decoySeq = ((synSeq + 1 - fakeLen) and 0xFFFFFFFFL)
                val newIdent = ((currIdent + 1) and 0xFFFF)
                fakeSent = true
                phase = HandshakePhase.DECOY_INJECTED

                return OutboundAction(
                    scheduleDecoy = true,
                    decoySeq = decoySeq,
                    newIdent = newIdent
                )
            }

            phase = HandshakePhase.TERMINATED
            throw IllegalStateException("unexpected outbound packet during handshake")
        }
    }

    /**
     * Evaluates an inbound packet from remote server to client.
     */
    fun processInbound(
        seq: Long,
        ack: Long,
        isSyn: Boolean,
        isAck: Boolean,
        isRst: Boolean,
        isFin: Boolean,
        payloadLen: Int
    ): InboundAction {
        synchronized(lock) {
            if (synSeq == -1L) {
                phase = HandshakePhase.TERMINATED
                throw IllegalStateException("unexpected inbound packet before outbound SYN")
            }

            // 1. Inbound SYN-ACK: SYN=1, ACK=1, payload=0
            if (isSyn && isAck && !isRst && !isFin && payloadLen == 0) {
                val expectedAck = ((synSeq + 1) and 0xFFFFFFFFL)
                if (ack != expectedAck) {
                    phase = HandshakePhase.TERMINATED
                    throw IllegalStateException("inbound SYN-ACK ack mismatch:  != ")
                }
                if (synAckSeq != -1L && synAckSeq != seq) {
                    phase = HandshakePhase.TERMINATED
                    throw IllegalStateException("inbound SYN-ACK seq change:  != ")
                }
                synAckSeq = seq
                phase = HandshakePhase.SYN_ACK_RECEIVED
                return InboundAction()
            }

            // 2. Inbound ACK for decoy or post-handshake: ACK=1, SYN=0, payload=0
            if (isAck && !isSyn && !isRst && !isFin && payloadLen == 0 && (fakeSent || phase == HandshakePhase.DECOY_INJECTED)) {
                val expectedSeq = ((synAckSeq + 1) and 0xFFFFFFFFL)
                if (synAckSeq == -1L || seq != expectedSeq) {
                    phase = HandshakePhase.TERMINATED
                    throw IllegalStateException("inbound ACK seq mismatch:  != ")
                }
                val expectedAck = ((synSeq + 1) and 0xFFFFFFFFL)
                if (ack != expectedAck) {
                    phase = HandshakePhase.TERMINATED
                    throw IllegalStateException("inbound ACK ack mismatch:  != ")
                }

                phase = HandshakePhase.DECOY_ACKNOWLEDGED
                return InboundAction(decoyAcknowledged = true)
            }

            phase = HandshakePhase.TERMINATED
            throw IllegalStateException("unexpected inbound packet")
        }
    }
}
