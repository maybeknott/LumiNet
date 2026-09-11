package com.luminet.android.tunnel

import java.security.MessageDigest
import java.util.HashSet

data class PacSyncDelta(
    val addedDomains: List<String>,
    val removedDomains: List<String>,
    val previousChecksum: String,
    val newChecksum: String
)

class PacDiffSynchronizer(initialRules: List<String>) {
    private val activeRules = HashSet<String>()

    init {
        for (r in initialRules) {
            val trimmed = r.trim().lowercase()
            if (trimmed.isNotEmpty()) {
                activeRules.add(trimmed)
            }
        }
    }

    fun computeDelta(upstreamRules: List<String>): PacSyncDelta {
        val upstreamSet = HashSet<String>()
        for (r in upstreamRules) {
            val trimmed = r.trim().lowercase()
            if (trimmed.isNotEmpty()) {
                upstreamSet.add(trimmed)
            }
        }

        val added = upstreamSet.filter { !activeRules.contains(it) }.sorted()
        val removed = activeRules.filter { !upstreamSet.contains(it) }.sorted()

        return PacSyncDelta(
            addedDomains = added,
            removedDomains = removed,
            previousChecksum = currentChecksum(),
            newChecksum = computeChecksumForSet(upstreamSet)
        )
    }

    fun applyDelta(delta: PacSyncDelta): Int {
        if (currentChecksum() != delta.previousChecksum) {
            throw IllegalStateException("Checksum mismatch: concurrent modification")
        }

        for (rem in delta.removedDomains) {
            activeRules.remove(rem)
        }
        for (add in delta.addedDomains) {
            activeRules.add(add)
        }

        if (currentChecksum() != delta.newChecksum) {
            throw IllegalStateException("Post-apply checksum mismatch")
        }

        return activeRules.size
    }

    fun currentChecksum(): String {
        return computeChecksumForSet(activeRules)
    }

    fun containsRule(domain: String): Boolean {
        return activeRules.contains(domain.trim().lowercase())
    }

    fun totalRules(): Int = activeRules.size

    private fun computeChecksumForSet(set: Set<String>): String {
        val list = set.sorted()
        val md = MessageDigest.getInstance("SHA-256")
        for (item in list) {
            md.update(item.toByteArray(Charsets.UTF_8))
            md.update("\n".toByteArray(Charsets.UTF_8))
        }
        return md.digest().joinToString("") { "%02x".format(it) }
    }
}
