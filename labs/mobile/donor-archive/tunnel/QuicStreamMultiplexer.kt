package com.luminet.android.tunnel

import java.util.TreeMap

enum class QuicStreamType {
    CLIENT_BIDIRECTIONAL,
    SERVER_BIDIRECTIONAL,
    CLIENT_UNIDIRECTIONAL,
    SERVER_UNIDIRECTIONAL
}

data class QuicStreamFrame(
    val streamId: Long,
    val offset: Long,
    val fin: Boolean,
    val data: ByteArray
)

class QuicStreamMultiplexer(val defaultStreamWindow: Long = 65536) {
    private class StreamState(val streamType: QuicStreamType, var maxSendCredit: Long) {
        var sendOffset: Long = 0
        var recvOffset: Long = 0
        val receivedChunks = TreeMap<Long, ByteArray>()
        var finReceived: Boolean = false
        var finOffset: Long = -1
    }

    private val streams = HashMap<Long, StreamState>()
    private var nextClientBidi: Long = 0
    private var nextClientUni: Long = 2

    fun openStream(streamType: QuicStreamType): Long {
        val streamId = when (streamType) {
            QuicStreamType.CLIENT_BIDIRECTIONAL -> {
                val id = nextClientBidi
                nextClientBidi += 4
                id
            }
            QuicStreamType.CLIENT_UNIDIRECTIONAL -> {
                val id = nextClientUni
                nextClientUni += 4
                id
            }
            QuicStreamType.SERVER_BIDIRECTIONAL -> 1
            QuicStreamType.SERVER_UNIDIRECTIONAL -> 3
        }

        streams[streamId] = StreamState(streamType, defaultStreamWindow)
        return streamId
    }

    fun writeStreamData(streamId: Long, data: ByteArray, fin: Boolean): QuicStreamFrame {
        val stream = streams[streamId] ?: throw NoSuchElementException("Stream not found")
        val length = data.size.toLong()
        if (stream.sendOffset + length > stream.maxSendCredit) {
            throw IllegalStateException("Flow control window exceeded")
        }

        val frame = QuicStreamFrame(
            streamId = streamId,
            offset = stream.sendOffset,
            fin = fin,
            data = data
        )

        stream.sendOffset += length
        return frame
    }

    fun receiveStreamFrame(frame: QuicStreamFrame): ByteArray {
        val stream = streams.getOrPut(frame.streamId) {
            StreamState(QuicStreamType.CLIENT_BIDIRECTIONAL, defaultStreamWindow)
        }

        if (frame.fin) {
            stream.finReceived = true
            stream.finOffset = frame.offset + frame.data.size
        }

        stream.receivedChunks[frame.offset] = frame.data

        val assembled = ArrayList<Byte>()
        while (stream.receivedChunks.containsKey(stream.recvOffset)) {
            val chunk = stream.receivedChunks.remove(stream.recvOffset)!!
            stream.recvOffset += chunk.size
            for (b in chunk) assembled.add(b)
        }

        return assembled.toByteArray()
    }

    fun isStreamClosed(streamId: Long): Boolean {
        val stream = streams[streamId] ?: return false
        return stream.finReceived && stream.recvOffset >= stream.finOffset
    }
}
