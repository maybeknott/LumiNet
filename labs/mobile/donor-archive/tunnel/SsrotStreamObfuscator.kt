package com.luminet.android.tunnel

import java.nio.ByteBuffer
import java.security.MessageDigest
import javax.crypto.Mac
import javax.crypto.spec.SecretKeySpec

enum class SsrotObfsType {
    PLAIN,
    HTTP_SIMPLE,
    TLS12_TICKET_AUTH
}

enum class SsrotProtocolType {
    ORIGIN,
    AUTH_SHA1_V4,
    AUTH_CHAIN_A
}

data class SsrotConfig(
    val password: String,
    val protocol: SsrotProtocolType,
    val obfs: SsrotObfsType,
    val obfsParam: String = ""
)

class SsrotStreamObfuscator(val config: SsrotConfig) {
    private var sendId: Int = 1
    private var recvId: Int = 1
    private val secretKey: ByteArray

    init {
        val md = MessageDigest.getInstance("MD5")
        secretKey = md.digest(config.password.toByteArray(Charsets.UTF_8))
    }

    fun clientEncodeHandshake(targetHost: String, targetPort: Int, payload: ByteArray): ByteArray {
        val hostBytes = targetHost.toByteArray(Charsets.UTF_8)
        val buffer = ByteBuffer.allocate(2 + hostBytes.len() + 2 + payload.size)
        buffer.put(3.toByte())
        buffer.put(hostBytes.size.toByte())
        buffer.put(hostBytes)
        buffer.putShort(targetPort.toShort())
        buffer.put(payload)

        val raw = buffer.array()
        val protoWrapped = wrapProtocol(raw)
        return wrapObfs(protoWrapped)
    }

    private fun ByteArray.len(): Int = this.size

    fun serverDecodeHandshake(data: ByteArray): Triple<String, Int, ByteArray> {
        val unwrappedObfs = unwrapObfs(data)
        val unwrappedProto = unwrapProtocol(unwrappedObfs)

        if (unwrappedProto.size < 4) {
            throw IllegalArgumentException("Handshake data too short")
        }

        val atyp = unwrappedProto[0].toInt()
        if (atyp != 3) {
            throw IllegalArgumentException("Unsupported atyp: $atyp")
        }

        val hostLen = unwrappedProto[1].toInt() and 0xff
        if (unwrappedProto.size < 2 + hostLen + 2) {
            throw IllegalArgumentException("Incomplete host/port")
        }

        val host = String(unwrappedProto, 2, hostLen, Charsets.UTF_8)
        val portBuf = ByteBuffer.wrap(unwrappedProto, 2 + hostLen, 2)
        val port = portBuf.short.toInt() and 0xffff
        val payload = unwrappedProto.copyOfRange(4 + hostLen, unwrappedProto.size)

        return Triple(host, port, payload)
    }

    fun encodeChunk(data: ByteArray): ByteArray {
        sendId++
        val chunk = ByteBuffer.allocate(2 + 4 + data.size + 4)
        chunk.putShort(data.size.toShort())
        chunk.putInt(sendId)

        for (i in data.indices) {
            val k = secretKey[i % secretKey.size]
            chunk.put((data[i].toInt() xor k.toInt()).toByte())
        }

        val mac = Mac.getInstance("HmacSHA256")
        mac.init(SecretKeySpec(secretKey, "HmacSHA256"))
        mac.update(chunk.array(), 0, 6 + data.size)
        val tag = mac.doFinal()

        chunk.put(tag, 0, 4)
        return chunk.array()
    }

    fun decodeChunk(data: ByteArray): ByteArray {
        if (data.size < 10) {
            throw IllegalArgumentException("Chunk too small")
        }

        val buf = ByteBuffer.wrap(data)
        val length = buf.short.toInt() and 0xffff
        if (data.size < 6 + length + 4) {
            throw IllegalArgumentException("Incomplete chunk data")
        }

        recvId = buf.int

        val mac = Mac.getInstance("HmacSHA256")
        mac.init(SecretKeySpec(secretKey, "HmacSHA256"))
        mac.update(data, 0, 6 + length)
        val tag = mac.doFinal()

        for (i in 0 until 4) {
            if (data[6 + length + i] != tag[i]) {
                throw SecurityException("Invalid chunk HMAC tag")
            }
        }

        val unmasked = ByteArray(length)
        for (i in 0 until length) {
            val k = secretKey[i % secretKey.size]
            unmasked[i] = (data[6 + i].toInt() xor k.toInt()).toByte()
        }

        return unmasked
    }

    private fun wrapProtocol(data: ByteArray): ByteArray {
        return when (config.protocol) {
            SsrotProtocolType.ORIGIN -> data
            else -> {
                val mac = Mac.getInstance("HmacSHA1")
                mac.init(SecretKeySpec(secretKey, "HmacSHA1"))
                val tag = mac.doFinal(data)

                val out = ByteBuffer.allocate(4 + 4 + data.size)
                out.put("SSR\u0001".toByteArray(Charsets.UTF_8))
                out.put(tag, 0, 4)
                out.put(data)
                out.array()
            }
        }
    }

    private fun unwrapProtocol(data: ByteArray): ByteArray {
        return when (config.protocol) {
            SsrotProtocolType.ORIGIN -> data
            else -> {
                if (data.size < 8 || String(data, 0, 3, Charsets.UTF_8) != "SSR") {
                    throw IllegalArgumentException("Invalid protocol header")
                }
                val payload = data.copyOfRange(8, data.size)
                val mac = Mac.getInstance("HmacSHA1")
                mac.init(SecretKeySpec(secretKey, "HmacSHA1"))
                val tag = mac.doFinal(payload)

                for (i in 0 until 4) {
                    if (data[4 + i] != tag[i]) {
                        throw SecurityException("Protocol HMAC mismatch")
                    }
                }
                payload
            }
        }
    }

    private fun wrapObfs(data: ByteArray): ByteArray {
        return when (config.obfs) {
            SsrotObfsType.PLAIN -> data
            SsrotObfsType.HTTP_SIMPLE -> {
                val host = if (config.obfsParam.isEmpty()) "cloudflare.com" else config.obfsParam
                val header = "GET / HTTP/1.1\r\nHost: $host\r\nUser-Agent: Mozilla/5.0\r\nAccept: */*\r\nContent-Length: ${data.size}\r\n\r\n"
                val hBytes = header.toByteArray(Charsets.UTF_8)
                val out = ByteArray(hBytes.size + data.size)
                System.arraycopy(hBytes, 0, out, 0, hBytes.size)
                System.arraycopy(data, 0, out, hBytes.size, data.size)
                out
            }
            SsrotObfsType.TLS12_TICKET_AUTH -> {
                val out = ByteBuffer.allocate(5 + data.size)
                out.put(0x16.toByte())
                out.put(0x03.toByte())
                out.put(0x03.toByte())
                out.putShort(data.size.toShort())
                out.put(data)
                out.array()
            }
        }
    }

    private fun unwrapObfs(data: ByteArray): ByteArray {
        return when (config.obfs) {
            SsrotObfsType.PLAIN -> data
            SsrotObfsType.HTTP_SIMPLE -> {
                val delim = "\r\n\r\n".toByteArray(Charsets.UTF_8)
                val pos = indexOfSequence(data, delim)
                if (pos == -1) {
                    throw IllegalArgumentException("Invalid HTTP framing")
                }
                data.copyOfRange(pos + 4, data.size)
            }
            SsrotObfsType.TLS12_TICKET_AUTH -> {
                if (data.size < 5 || data[0] != 0x16.toByte()) {
                    throw IllegalArgumentException("Invalid TLS ticket framing")
                }
                val buf = ByteBuffer.wrap(data, 3, 2)
                val len = buf.short.toInt() and 0xffff
                if (data.size < 5 + len) {
                    throw IllegalArgumentException("Incomplete TLS record")
                }
                data.copyOfRange(5, 5 + len)
            }
        }
    }

    private fun indexOfSequence(source: ByteArray, target: ByteArray): Int {
        for (i in 0..source.size - target.size) {
            var match = true
            for (j in target.indices) {
                if (source[i + j] != target[j]) {
                    match = false
                    break
                }
            }
            if (match) return i
        }
        return -1
    }
}
