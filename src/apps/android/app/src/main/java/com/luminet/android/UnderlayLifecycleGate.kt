package com.luminet.android

/**
 * Small, platform-independent lifecycle epoch used by the underlay tracker.
 * Callers still serialize access with the tracker lock; this type exists so the
 * start/stop invalidation contract can be unit-tested without Android framework
 * objects.
 */
internal class UnderlayLifecycleGate {
    var generation: Long = 0
        private set

    var active: Boolean = false
        private set

    fun start(): Long {
        generation += 1
        active = true
        return generation
    }

    fun stop() {
        generation += 1
        active = false
    }

    fun isCurrent(snapshotGeneration: Long): Boolean =
        active && generation == snapshotGeneration
}
