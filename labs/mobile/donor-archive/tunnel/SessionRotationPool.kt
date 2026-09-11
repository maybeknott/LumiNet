package com.luminet.android.tunnel

enum class AndroidAccountStatus {
    READY, IN_USE, COOLING_DOWN, LOCKED
}

data class AndroidManagedAccount(
    val accountId: String,
    val token: String,
    var usesCount: Int = 0,
    val maxUses: Int = 10,
    var status: AndroidAccountStatus = AndroidAccountStatus.READY,
    var cooldownUntilSec: Long = 0
)

class SessionRotationPool(private val defaultCooldownSec: Long = 60) {
    private val accounts = mutableMapOf<String, AndroidManagedAccount>()
    private val rotationOrder = mutableListOf<String>()
    private var cursor = 0

    fun addAccount(accountId: String, token: String, maxUses: Int) {
        accounts[accountId] = AndroidManagedAccount(
            accountId = accountId,
            token = token,
            maxUses = maxUses
        )
        rotationOrder.add(accountId)
    }

    fun acquireAccount(nowSec: Long): Pair<String, String>? {
        if (rotationOrder.isEmpty()) return null

        for (acc in accounts.values) {
            if (acc.status == AndroidAccountStatus.COOLING_DOWN && nowSec >= acc.cooldownUntilSec) {
                acc.status = AndroidAccountStatus.READY
                acc.usesCount = 0
            }
        }

        val n = rotationOrder.size
        for (i in 0 until n) {
            val id = rotationOrder[cursor % n]
            cursor++

            val acc = accounts[id]
            if (acc != null && acc.status == AndroidAccountStatus.READY) {
                acc.usesCount++
                if (acc.usesCount >= acc.maxUses) {
                    acc.status = AndroidAccountStatus.COOLING_DOWN
                    acc.cooldownUntilSec = nowSec + defaultCooldownSec
                }
                return acc.accountId to acc.token
            }
        }
        return null
    }

    fun markLocked(accountId: String) {
        accounts[accountId]?.let { it.status = AndroidAccountStatus.LOCKED }
    }

    fun availableCount(nowSec: Long): Int {
        return accounts.values.count {
            it.status == AndroidAccountStatus.READY ||
                    (it.status == AndroidAccountStatus.COOLING_DOWN && nowSec >= it.cooldownUntilSec)
        }
    }
}
