package com.luminet.android.tunnel

import java.io.ByteArrayOutputStream
import java.nio.ByteBuffer
import java.util.concurrent.ConcurrentHashMap

enum class AndroidNatType {
    OPEN_INTERNET,
    FULL_CONE,
    RESTRICTED_CONE,
    PORT_RESTRICTED_CONE,
    SYMMETRIC
}

enum class AndroidPunchState {
    INITIAL,
    PROBING,
    ESTABLISHED,
    FALLBACK_RELAY
}

data class AndroidPeerCandidate(
    val peerId: String,
    val localEndpoint: String,
    val reflexiveEndpoint: String,
    val natType: AndroidNatType
)

class NatTraversalTunnel(
    val localPeerId: String,
    val localNat: AndroidNatType
) {
    val magic: Int = 0x564E5431 // "VNT1"
    private val peers = ConcurrentHashMap<String, AndroidPunchState>()

    fun canDirectPunch(a: AndroidNatType, b: AndroidNatType): Boolean {
        if (a == AndroidNatType.SYMMETRIC && b == AndroidNatType.SYMMETRIC) return false
        if ((a == AndroidNatType.PORT_RESTRICTED_CONE && b == AndroidNatType.SYMMETRIC) ||
            (a == AndroidNatType.SYMMETRIC && b == AndroidNatType.PORT_RESTRICTED_CONE)) return false
        return true
    }

    fun craftPunchPacket(seq: Int): ByteArray {
        val out = ByteArrayOutputStream()
        val header = ByteBuffer.allocate(10)
        header.putInt(magic)
        header.putInt(seq)
        val idBytes = localPeerId.toByteArray(Charsets.UTF_8)
        header.putShort(idBytes.size.toShort())
        out.write(header.array())
        out.write(idBytes)
        return out.toByteArray()
    }

    fun parsePunchPacket(data: ByteArray): Pair<Int, String>? {
        if (data.size < 10) return null
        val buf = ByteBuffer.wrap(data)
        val mag = buf.int
        if (mag != magic) return null
        val seq = buf.int
        val idLen = buf.short.toInt() and 0xFFFF
        if (data.size < 10 + idLen) return null
        val id = String(data, 10, idLen, Charsets.UTF_8)
        return Pair(seq, id)
    }

    fun initiatePeerPunch(candidate: AndroidPeerCandidate): AndroidPunchState {
        val state = if (canDirectPunch(localNat, candidate.natType)) {
            AndroidPunchState.PROBING
        } else {
            AndroidPunchState.FALLBACK_RELAY
        }
        peers[candidate.peerId] = state
        return state
    }

    fun markEstablished(peerId: String): Boolean {
        if (peers.containsKey(peerId)) {
            peers[peerId] = AndroidPunchState.ESTABLISHED
            return true
        }
        return false
    }
}
