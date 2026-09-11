package com.luminet.android.tunnel

import java.io.ByteArrayInputStream
import java.io.ByteArrayOutputStream
import java.io.DataInputStream
import java.io.DataOutputStream
import java.nio.ByteBuffer
import java.nio.ByteOrder
import java.nio.charset.StandardCharsets

/**
 * TLS Session Ticket Obfuscator, Active Probing Deflector, and ECH Config Parser.
 *
 * Ported and unified from `psiphon-tls-master`.
 * Provides standard ticket size normalization to defeat TLS fingerprinting,
 * active probing deflection routing, and Encrypted Client Hello (ECH) Draft-18 parsing.
 */
object TlsObfuscatorConstants {
    val CANONICAL_PADDED_TICKET_SIZES = intArrayOf(160, 176, 192, 208, 218, 224, 240, 255)
}

object TicketPadder {
    fun padTicket(ticket: ByteArray): ByteArray {
        val currLen = ticket.size
        var targetSize = 0
        for (s in TlsObfuscatorConstants.CANONICAL_PADDED_TICKET_SIZES) {
            if (s >= currLen) {
                targetSize = s
                break
            }
        }
        if (targetSize == 0) {
            targetSize = (currLen + 15) and 15.inv()
        }

        val out = ByteArray(targetSize)
        System.arraycopy(ticket, 0, out, 0, currLen)
        return out
    }

    fun unpadTicket(padded: ByteArray): ByteArray {
        var end = padded.size
        while (end > 0 && padded[end - 1] == 0.toByte()) {
            end--
        }
        return padded.copyOfRange(0, end)
    }
}

data class ObfuscatedClientSessionState(
    val ticket: ByteArray,
    val vers: Int,
    val cipherSuite: Int,
    val masterSecret: ByteArray,
    val createdAt: Long,
    val ageAdd: Long,
    val useBy: Long
) {
    fun serialize(): ByteArray {
        val out = ByteArrayOutputStream(28 + masterSecret.size + ticket.size)
        val data = DataOutputStream(out)
        data.writeShort(vers)
        data.writeShort(cipherSuite)
        data.writeLong(createdAt)
        data.writeInt((ageAdd and 0xFFFFFFFFL).toInt())
        data.writeLong(useBy)

        data.writeShort(masterSecret.size)
        data.write(masterSecret)

        data.writeShort(ticket.size)
        data.write(ticket)
        data.flush()
        return out.toByteArray()
    }

    companion object {
        fun create(
            ticket: ByteArray,
            vers: Int,
            cipherSuite: Int,
            masterSecret: ByteArray,
            createdAt: Long,
            ageAdd: Long,
            useBy: Long
        ): ObfuscatedClientSessionState {
            return ObfuscatedClientSessionState(
                ticket = TicketPadder.padTicket(ticket),
                vers = vers,
                cipherSuite = cipherSuite,
                masterSecret = masterSecret.clone(),
                createdAt = createdAt,
                ageAdd = ageAdd,
                useBy = useBy
            )
        }

        fun deserialize(bytes: ByteArray): ObfuscatedClientSessionState {
            if (bytes.size < 28) {
                throw IllegalArgumentException("Buffer too short for session state: ${bytes.size} < 28")
            }
            val stream = ByteArrayInputStream(bytes)
            val data = DataInputStream(stream)

            val vers = data.readUnsignedShort()
            val cipherSuite = data.readUnsignedShort()
            val createdAt = data.readLong()
            val ageAdd = data.readInt().toLong() and 0xFFFFFFFFL
            val useBy = data.readLong()

            val secretLen = data.readUnsignedShort()
            val masterSecret = ByteArray(secretLen)
            data.readFully(masterSecret)

            val ticketLen = data.readUnsignedShort()
            val ticket = ByteArray(ticketLen)
            data.readFully(ticket)

            return ObfuscatedClientSessionState(
                ticket = ticket,
                vers = vers,
                cipherSuite = cipherSuite,
                masterSecret = masterSecret,
                createdAt = createdAt,
                ageAdd = ageAdd,
                useBy = useBy
            )
        }
    }

    override fun equals(other: Any?): Boolean {
        if (this === other) return true
        if (other !is ObfuscatedClientSessionState) return false
        if (!ticket.contentEquals(other.ticket)) return false
        if (vers != other.vers) return false
        if (cipherSuite != other.cipherSuite) return false
        if (!masterSecret.contentEquals(other.masterSecret)) return false
        if (createdAt != other.createdAt) return false
        if (ageAdd != other.ageAdd) return false
        if (useBy != other.useBy) return false
        return true
    }

    override fun hashCode(): Int {
        var result = ticket.contentHashCode()
        result = 31 * result + vers
        result = 31 * result + cipherSuite
        result = 31 * result + masterSecret.contentHashCode()
        result = 31 * result + createdAt.hashCode()
        result = 31 * result + ageAdd.hashCode()
        result = 31 * result + useBy.hashCode()
        return result
    }
}

class TlsPassthroughDeflector(
    val passthroughAddress: String?,
    val authorizedTokens: List<String>
) {
    fun shouldDeflect(presentedToken: String?): Boolean {
        if (passthroughAddress.isNullOrEmpty()) {
            return false
        }
        if (presentedToken.isNullOrEmpty()) {
            return true
        }
        return !authorizedTokens.contains(presentedToken)
    }
}

data class EchCipher(
    val kdfId: Int,
    val aeadId: Int
)

data class EchConfig(
    val version: Int,
    val configId: Int,
    val kemId: Int,
    val publicKey: ByteArray,
    val cipherSuites: List<EchCipher>,
    val maxNameLength: Int,
    val publicName: String
) {
    override fun equals(other: Any?): Boolean {
        if (this === other) return true
        if (other !is EchConfig) return false
        if (version != other.version) return false
        if (configId != other.configId) return false
        if (kemId != other.kemId) return false
        if (!publicKey.contentEquals(other.publicKey)) return false
        if (cipherSuites != other.cipherSuites) return false
        if (maxNameLength != other.maxNameLength) return false
        if (publicName != other.publicName) return false
        return true
    }

    override fun hashCode(): Int {
        var result = version
        result = 31 * result + configId
        result = 31 * result + kemId
        result = 31 * result + publicKey.contentHashCode()
        result = 31 * result + cipherSuites.hashCode()
        result = 31 * result + maxNameLength
        result = 31 * result + publicName.hashCode()
        return result
    }
}

object EchConfigParser {
    fun parseConfigList(data: ByteArray): List<EchConfig> {
        if (data.size < 2) {
            throw IllegalArgumentException("ECHConfigList too short")
        }

        val listLen = ((data[0].toInt() and 0xFF) shl 8) or (data[1].toInt() and 0xFF)
        if (data.size != 2 + listLen) {
            throw IllegalArgumentException("Malformed ECHConfigList length")
        }

        var offset = 2
        val configs = mutableListOf<EchConfig>()

        while (offset < data.size) {
            if (data.size < offset + 4) {
                throw IllegalArgumentException("Malformed ECHConfig header")
            }

            val vers = ((data[offset].toInt() and 0xFF) shl 8) or (data[offset + 1].toInt() and 0xFF)
            val cfgLen = ((data[offset + 2].toInt() and 0xFF) shl 8) or (data[offset + 3].toInt() and 0xFF)
            offset += 4

            if (data.size < offset + cfgLen) {
                throw IllegalArgumentException("Truncated ECHConfig body")
            }

            val entry = data.copyOfRange(offset, offset + cfgLen)
            offset += cfgLen

            if (entry.size < 5) {
                throw IllegalArgumentException("ECHConfig entry too short")
            }

            val cfgId = entry[0].toInt() and 0xFF
            val kemId = ((entry[1].toInt() and 0xFF) shl 8) or (entry[2].toInt() and 0xFF)
            val pkLen = ((entry[3].toInt() and 0xFF) shl 8) or (entry[4].toInt() and 0xFF)
            var cOffset = 5

            if (entry.size < cOffset + pkLen + 2) {
                throw IllegalArgumentException("Truncated ECH public key")
            }
            val publicKey = entry.copyOfRange(cOffset, cOffset + pkLen)
            cOffset += pkLen

            val ciphersLen = ((entry[cOffset].toInt() and 0xFF) shl 8) or (entry[cOffset + 1].toInt() and 0xFF)
            cOffset += 2

            if (entry.size < cOffset + ciphersLen + 2) {
                throw IllegalArgumentException("Truncated ECH ciphers")
            }

            val ciphers = mutableListOf<EchCipher>()
            val cEnd = cOffset + ciphersLen
            while (cOffset + 4 <= cEnd) {
                val kdf = ((entry[cOffset].toInt() and 0xFF) shl 8) or (entry[cOffset + 1].toInt() and 0xFF)
                val aead = ((entry[cOffset + 2].toInt() and 0xFF) shl 8) or (entry[cOffset + 3].toInt() and 0xFF)
                ciphers.add(EchCipher(kdf, aead))
                cOffset += 4
            }
            cOffset = cEnd

            val maxNameLen = entry[cOffset].toInt() and 0xFF
            cOffset++

            if (entry.size < cOffset + 1) {
                throw IllegalArgumentException("Missing public name length")
            }
            val nameLen = entry[cOffset].toInt() and 0xFF
            cOffset++

            if (entry.size < cOffset + nameLen) {
                throw IllegalArgumentException("Truncated public name")
            }
            val publicName = String(entry, cOffset, nameLen, StandardCharsets.UTF_8)

            configs.add(
                EchConfig(
                    version = vers,
                    configId = cfgId,
                    kemId = kemId,
                    publicKey = publicKey,
                    cipherSuites = ciphers,
                    maxNameLength = maxNameLen,
                    publicName = publicName
                )
            )
        }

        return configs
    }
}
