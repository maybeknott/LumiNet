package com.luminet.android.tunnel

data class AndroidEndpointProfile(
    val profileId: String,
    val serverHost: String,
    val serverPort: Int,
    val username: String,
    val encryptedSecret: ByteArray,
    val createdAtSec: Long,
    val expiresAtSec: Long
) {
    override fun equals(other: Any?): Boolean {
        if (this === other) return true
        if (javaClass != other?.javaClass) return false
        other as AndroidEndpointProfile
        return profileId == other.profileId
    }

    override fun hashCode(): Int = profileId.hashCode()
}

class EndpointCredentialVault(private val masterKey: ByteArray) {
    private val profiles = mutableMapOf<String, AndroidEndpointProfile>()

    fun storeProfile(
        profileId: String,
        host: String,
        port: Int,
        user: String,
        rawSecret: ByteArray,
        nowSec: Long,
        ttlSec: Long
    ) {
        val enc = ByteArray(rawSecret.size)
        for (i in rawSecret.indices) {
            val k = if (masterKey.isNotEmpty()) masterKey[i % masterKey.size] else 0
            enc[i] = (rawSecret[i].toInt() xor k.toInt()).toByte()
        }

        profiles[profileId] = AndroidEndpointProfile(
            profileId = profileId,
            serverHost = host,
            serverPort = port,
            username = user,
            encryptedSecret = enc,
            createdAtSec = nowSec,
            expiresAtSec = nowSec + ttlSec
        )
    }

    fun retrieveSecret(profileId: String, nowSec: Long): ByteArray? {
        val p = profiles[profileId] ?: return null
        if (nowSec > p.expiresAtSec) return null

        val dec = ByteArray(p.encryptedSecret.size)
        for (i in p.encryptedSecret.indices) {
            val k = if (masterKey.isNotEmpty()) masterKey[i % masterKey.size] else 0
            dec[i] = (p.encryptedSecret[i].toInt() xor k.toInt()).toByte()
        }
        return dec
    }

    fun isProfileValid(profileId: String, nowSec: Long): Boolean {
        val p = profiles[profileId] ?: return false
        return nowSec <= p.expiresAtSec
    }

    fun purgeExpired(nowSec: Long): Int {
        val before = profiles.size
        profiles.entries.removeAll { nowSec > it.value.expiresAtSec }
        return before - profiles.size
    }
}
