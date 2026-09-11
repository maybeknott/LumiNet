package com.luminet.android.tunnel

import java.nio.ByteBuffer

enum class QuicHeaderType {
    INITIAL,
    ZERO_RTT,
    HANDSHAKE,
    RETRY,
    ONE_RTT_SHORT
}

data class QuicPacketHeader(
    val headerType: QuicHeaderType,
    val version: Long,
    val destCid: ByteArray,
    val srcCid: ByteArray,
    val packetNumber: Long
)

class QuicPacketCodec {
    fun encodeVarint(value: Long): ByteArray {
        return when {
            value < (1L shl 6) -> byteArrayOf(value.toByte())
            value < (1L shl 14) -> byteArrayOf(
                (0x40 or ((value shr 8) and 0x3f).toInt()).toByte(),
                (value and 0xff).toByte()
            )
            value < (1L shl 30) -> {
                val out = ByteArray(4)
                out[0] = (0x80 or ((value shr 24) and 0x3f).toInt()).toByte()
                out[1] = ((value shr 16) and 0xff).toByte()
                out[2] = ((value shr 8) and 0xff).toByte()
                out[3] = (value and 0xff).toByte()
                out
            }
            else -> {
                val out = ByteArray(8)
                out[0] = (0xc0 or ((value shr 56) and 0x3f).toInt()).toByte()
                for (i in 1..7) {
                    out[i] = ((value shr ((7 - i) * 8)) and 0xff).toByte()
                }
                out
            }
        }
    }

    fun decodeVarint(data: ByteArray, offset: Int): Pair<Long, Int> {
        if (offset >= data.size) throw IllegalArgumentException("Varint EOF")
        val prefix = (data[offset].toInt() and 0xff) shr 6
        return when (prefix) {
            0 -> Pair((data[offset].toInt() and 0x3f).toLong(), 1)
            1 -> {
                if (offset + 2 > data.size) throw IllegalArgumentException("Varint truncated 2")
                val b0 = data[offset].toLong() and 0x3f
                val b1 = data[offset + 1].toLong() and 0xff
                Pair((b0 shl 8) or b1, 2)
            }
            2 -> {
                if (offset + 4 > data.size) throw IllegalArgumentException("Varint truncated 4")
                val b0 = data[offset].toLong() and 0x3f
                val b1 = data[offset + 1].toLong() and 0xff
                val b2 = data[offset + 2].toLong() and 0xff
                val b3 = data[offset + 3].toLong() and 0xff
                Pair((b0 shl 24) or (b1 shl 16) or (b2 shl 8) or b3, 4)
            }
            3 -> {
                if (offset + 8 > data.size) throw IllegalArgumentException("Varint truncated 8")
                var v = (data[offset].toLong() and 0x3f) shl 56
                for (i in 1..7) {
                    v = v or ((data[offset + i].toLong() and 0xff) shl ((7 - i) * 8))
                }
                Pair(v, 8)
            }
            else -> throw IllegalStateException()
        }
    }

    fun encodePacket(header: QuicPacketHeader, payload: ByteArray): ByteArray {
        val out = ArrayList<Byte>()
        if (header.headerType == QuicHeaderType.ONE_RTT_SHORT) {
            out.add((0x40 or 0x01).toByte())
            for (b in header.destCid) out.add(b)
            val pnBytes = ByteBuffer.allocate(2).putShort(header.packetNumber.toShort()).array()
            for (b in pnBytes) out.add(b)
            for (b in payload) out.add(b)
            return out.toByteArray()
        }

        val typeBits = when (header.headerType) {
            QuicHeaderType.INITIAL -> 0x00
            QuicHeaderType.ZERO_RTT -> 0x10
            QuicHeaderType.HANDSHAKE -> 0x20
            QuicHeaderType.RETRY -> 0x30
            QuicHeaderType.ONE_RTT_SHORT -> 0
        }
        out.add((0x80 or 0x40 or typeBits).toByte())

        val verBytes = ByteBuffer.allocate(4).putInt(header.version.toInt()).array()
        for (b in verBytes) out.add(b)

        out.add(header.destCid.size.toByte())
        for (b in header.destCid) out.add(b)

        out.add(header.srcCid.size.toByte())
        for (b in header.srcCid) out.add(b)

        val pnBytes = ByteBuffer.allocate(2).putShort(header.packetNumber.toShort()).array()
        val lenVar = encodeVarint((pnBytes.size + payload.size).toLong())
        for (b in lenVar) out.add(b)

        for (b in pnBytes) out.add(b)
        for (b in payload) out.add(b)
        return out.toByteArray()
    }

    fun decodePacket(data: ByteArray, destCidLen: Int): Pair<QuicPacketHeader, ByteArray> {
        if (data.isEmpty()) throw IllegalArgumentException("Empty packet")
        val firstByte = data[0].toInt() and 0xff
        val isLong = (firstByte and 0x80) != 0

        if (isLong) {
            if (data.size < 7) throw IllegalArgumentException("Long header truncated")
            val typeBits = (firstByte and 0x30) shr 4
            val hType = when (typeBits) {
                0x00 -> QuicHeaderType.INITIAL
                0x01 -> QuicHeaderType.ZERO_RTT
                0x02 -> QuicHeaderType.HANDSHAKE
                0x03 -> QuicHeaderType.RETRY
                else -> QuicHeaderType.INITIAL
            }

            val version = ByteBuffer.wrap(data, 1, 4).int.toLong() and 0xffffffffL
            var offset = 5

            val dcidLen = data[offset].toInt() and 0xff
            offset++
            val dcid = data.copyOfRange(offset, offset + dcidLen)
            offset += dcidLen

            val scidLen = data[offset].toInt() and 0xff
            offset++
            val scid = data.copyOfRange(offset, offset + scidLen)
            offset += scidLen

            val (payloadLen, vlen) = decodeVarint(data, offset)
            offset += vlen

            val pn = ByteBuffer.wrap(data, offset, 2).short.toLong() and 0xffffL
            offset += 2

            val payloadSize = (payloadLen - 2).toInt()
            val payload = data.copyOfRange(offset, offset + payloadSize)

            return Pair(
                QuicPacketHeader(hType, version, dcid, scid, pn),
                payload
            )
        } else {
            var offset = 1
            val dcid = data.copyOfRange(offset, offset + destCidLen)
            offset += destCidLen

            val pn = ByteBuffer.wrap(data, offset, 2).short.toLong() and 0xffffL
            offset += 2

            val payload = data.copyOfRange(offset, data.size)
            return Pair(
                QuicPacketHeader(QuicHeaderType.ONE_RTT_SHORT, 0, dcid, ByteArray(0), pn),
                payload
            )
        }
    }
}
