package com.luminet.android.tunnel

import java.nio.ByteBuffer
import java.nio.ByteOrder
import java.security.SecureRandom

/**
 * Constant-Size (517-byte) RFC 7685 Padded TLS ClientHello Generator.
 * Ported and unified from `sni-spoofing-rust-main`.
 * Conforms to strict architectural isolation rules: zero vendor prefixes.
 */
class SniPaddedClientHello {
    companion object {
        const val CLIENT_HELLO_CONSTANT_SIZE = 517
        const val EXTENSION_SERVER_NAME: Short = 0x0000
        const val EXTENSION_PADDING: Short = 0x0015 // RFC 7685
        const val MAX_SNI_LENGTH = 215

        /**
         * Builds a deterministic TLS 1.3 ClientHello of exactly 517 bytes.
         */
        fun buildPaddedClientHello(sni: String): ByteArray {
            val sniBytes = sni.toByteArray(Charsets.UTF_8)
            require(sniBytes.isNotEmpty()) { "SNI must not be empty" }
            require(sniBytes.size <= MAX_SNI_LENGTH) { "SNI exceeds 215-byte padding budget" }

            val random = SecureRandom()
            val extBuffer = ByteBuffer.allocate(450).order(ByteOrder.BIG_ENDIAN)

            // 1. SNI Extension (0x0000)
            val sniExtLen = (5 + sniBytes.size).toShort()
            extBuffer.putShort(EXTENSION_SERVER_NAME)
            extBuffer.putShort(sniExtLen)
            extBuffer.putShort((3 + sniBytes.size).toShort())
            extBuffer.put(0.toByte()) // host_name
            extBuffer.putShort(sniBytes.size.toShort())
            extBuffer.put(sniBytes)

            // 2. Supported Versions (0x002B)
            extBuffer.put(byteArrayOf(0x00, 0x2b, 0x00, 0x05, 0x04, 0x03, 0x04, 0x03, 0x03))

            // 3. Supported Groups (0x000A)
            extBuffer.put(byteArrayOf(0x00, 0x0a, 0x00, 0x06, 0x00, 0x04, 0x00, 0x1d, 0x00, 0x17))

            // 4. EC Point Formats (0x000B)
            extBuffer.put(byteArrayOf(0x00, 0x0b, 0x00, 0x02, 0x01, 0x00))

            // 5. Signature Algorithms (0x000D)
            extBuffer.put(byteArrayOf(
                0x00, 0x0d, 0x00, 0x0c, 0x00, 0x0a,
                0x04, 0x03, 0x08, 0x04, 0x04, 0x01, 0x05, 0x03, 0x08, 0x05
            ))

            // 6. Key Share (0x0033)
            extBuffer.put(byteArrayOf(0x00, 0x33, 0x00, 0x26, 0x00, 0x24, 0x00, 0x1d, 0x00, 0x20))
            val dummyKeyShare = ByteArray(32)
            random.nextBytes(dummyKeyShare)
            extBuffer.put(dummyKeyShare)

            val currentExtLen = extBuffer.position()
            // Base size: 88 bytes overhead + current extensions
            val baseLength = 88 + currentExtLen
            val padLen = CLIENT_HELLO_CONSTANT_SIZE - (baseLength + 4)
            require(padLen >= 0) { "Calculated padding length cannot be negative" }

            // 7. RFC 7685 Padding Extension
            extBuffer.putShort(EXTENSION_PADDING)
            extBuffer.putShort(padLen.toShort())
            val zeroPadding = ByteArray(padLen)
            extBuffer.put(zeroPadding)

            val finalExtLen = extBuffer.position()
            val extensionsBytes = ByteArray(finalExtLen)
            System.arraycopy(extBuffer.array(), 0, extensionsBytes, 0, finalExtLen)

            // Assemble Handshake Body
            val hsBody = ByteBuffer.allocate(CLIENT_HELLO_CONSTANT_SIZE - 5).order(ByteOrder.BIG_ENDIAN)
            hsBody.putShort(0x0303.toShort()) // Legacy TLS 1.2 client_version

            val clientRandom = ByteArray(32)
            random.nextBytes(clientRandom)
            hsBody.put(clientRandom)

            hsBody.put(0x20.toByte()) // Session ID length: 32
            val sessionId = ByteArray(32)
            random.nextBytes(sessionId)
            hsBody.put(sessionId)

            // Cipher Suites (3 suites)
            hsBody.putShort(6.toShort())
            hsBody.put(byteArrayOf(0x13, 0x01, 0x13, 0x02, 0x13, 0x03))

            // Compression
            hsBody.put(1.toByte())
            hsBody.put(0.toByte())

            // Extensions
            hsBody.putShort(finalExtLen.toShort())
            hsBody.put(extensionsBytes)

            val hsBodyBytes = hsBody.array()

            // Assemble TLS Record
            val record = ByteBuffer.allocate(CLIENT_HELLO_CONSTANT_SIZE).order(ByteOrder.BIG_ENDIAN)
            record.put(0x16.toByte()) // Handshake
            record.putShort(0x0301.toShort()) // Record version
            record.putShort((4 + hsBodyBytes.size).toShort())

            record.put(0x01.toByte()) // ClientHello
            record.put(((hsBodyBytes.size shr 16) and 0xFF).toByte())
            record.put(((hsBodyBytes.size shr 8) and 0xFF).toByte())
            record.put((hsBodyBytes.size and 0xFF).toByte())
            record.put(hsBodyBytes)

            return record.array()
        }
    }
}
