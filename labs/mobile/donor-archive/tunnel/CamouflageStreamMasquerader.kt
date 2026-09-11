package com.luminet.android.tunnel

enum class AndroidProbeAction {
    ACCEPT_STREAM, DEFLECT_TO_DECOY, DROP_CONNECTION
}

class CamouflageStreamMasquerader(
    private val sharedSecret: ByteArray,
    val decoyHost: String
) {
    private val validUserIds = mutableListOf<ByteArray>()

    fun registerUser(userId: ByteArray) {
        validUserIds.add(userId.copyOf(16))
    }

    fun generatePreamble(userId: ByteArray): ByteArray {
        val out = ByteArray(32)
        val salt = ByteArray(16) { 0x5a.toByte() }
        System.arraycopy(salt, 0, out, 0, 16)

        val secLen = if (sharedSecret.isNotEmpty()) sharedSecret.size else 1
        for (i in 0 until 16) {
            val secByte = if (sharedSecret.isNotEmpty()) sharedSecret[i % secLen] else 0
            val mask = (secByte.toInt() xor salt[i].toInt()).toByte()
            val uByte = if (i < userId.size) userId[i] else 0
            out[16 + i] = (uByte.toInt() xor mask.toInt()).toByte()
        }
        return out
    }

    fun inspectInboundStream(preamble: ByteArray): AndroidProbeAction {
        if (preamble.size < 32) return AndroidProbeAction.DEFLECT_TO_DECOY

        val salt = preamble.copyOfRange(0, 16)
        val candidateUid = ByteArray(16)
        val secLen = if (sharedSecret.isNotEmpty()) sharedSecret.size else 1

        for (i in 0 until 16) {
            val secByte = if (sharedSecret.isNotEmpty()) sharedSecret[i % secLen] else 0
            val mask = (secByte.toInt() xor salt[i].toInt()).toByte()
            candidateUid[i] = (preamble[16 + i].toInt() xor mask.toInt()).toByte()
        }

        for (valid in validUserIds) {
            if (valid.contentEquals(candidateUid)) {
                return AndroidProbeAction.ACCEPT_STREAM
            }
        }
        return AndroidProbeAction.DEFLECT_TO_DECOY
    }
}
