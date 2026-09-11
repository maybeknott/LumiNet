package com.luminet.android.tunnel

data class QuicTunnelMetrics(
    val connectionState: QuicConnectionState,
    val totalDatagramsSent: Long,
    val totalDatagramsReceived: Long,
    val activeStreams: Int,
    val evasionActive: Boolean
)

class QuicEvasionTunnelCoordinator(
    val destCid: ByteArray,
    val srcCid: ByteArray,
    clientRandom: ByteArray,
    serverRandom: ByteArray,
    val evasionActive: Boolean
) {
    private val multiplexer = QuicStreamMultiplexer(65536)
    private val connection = QuicConnectionController(65536).apply {
        state = QuicConnectionState.ESTABLISHED
    }
    private val masquerader = SniSegmentationMasquerader(SniSegmentationStrategy.MID_SNI_SPLIT, 8, 32)
    private val replaySession = ReplayResistantTunnelSession(
        ReplayResistantConfig(),
        clientRandom,
        serverRandom
    )
    private val codec = QuicPacketCodec()
    private var nextPacketNum: Long = 1
    private var totalSent: Long = 0
    private var totalRecv: Long = 0

    fun openTunnelStream(): Long {
        return multiplexer.openStream(QuicStreamType.CLIENT_BIDIRECTIONAL)
    }

    fun prepareOutboundDatagram(streamId: Long, appData: ByteArray, timestampSecs: Long): List<ByteArray> {
        val streamFrame = multiplexer.writeStreamData(streamId, appData, false)
        // Serialize frame payload simply: [streamId: 8][offset: 8][fin: 1][data]
        val frameBytes = java.nio.ByteBuffer.allocate(17 + streamFrame.data.size).apply {
            putLong(streamFrame.streamId)
            putLong(streamFrame.offset)
            put(if (streamFrame.fin) 1.toByte() else 0.toByte())
            put(streamFrame.data)
        }.array()

        val hdr = QuicPacketHeader(
            headerType = QuicHeaderType.ONE_RTT_SHORT,
            version = 0,
            destCid = destCid,
            srcCid = srcCid,
            packetNumber = nextPacketNum
        )
        val quicPkt = codec.encodePacket(hdr, frameBytes)

        val sealed = replaySession.sealPacket(nextPacketNum, timestampSecs, quicPkt)
        connection.onPacketSent(nextPacketNum, sealed.size, timestampSecs * 1000)

        nextPacketNum++
        totalSent++

        return if (evasionActive) {
            masquerader.segmentStream(sealed, nextPacketNum)
        } else {
            listOf(sealed)
        }
    }

    fun processInboundDatagram(sealedDatagram: ByteArray, currentTimeSecs: Long): Pair<Long, ByteArray> {
        val (seq, _, quicPkt) = replaySession.openPacket(sealedDatagram, currentTimeSecs)
        connection.onAckReceived(seq, currentTimeSecs * 1000)
        totalRecv++

        val (_, payload) = codec.decodePacket(quicPkt, destCid.size)
        val buf = java.nio.ByteBuffer.wrap(payload)
        val streamId = buf.long
        val offset = buf.long
        val fin = buf.get() == 1.toByte()
        val data = ByteArray(payload.size - 17)
        buf.get(data)

        val frame = QuicStreamFrame(streamId, offset, fin, data)
        val assembled = multiplexer.receiveStreamFrame(frame)

        return Pair(streamId, assembled)
    }

    fun getTunnelMetrics(): QuicTunnelMetrics {
        return QuicTunnelMetrics(
            connectionState = connection.state,
            totalDatagramsSent = totalSent,
            totalDatagramsReceived = totalRecv,
            activeStreams = 1,
            evasionActive = evasionActive
        )
    }
}
