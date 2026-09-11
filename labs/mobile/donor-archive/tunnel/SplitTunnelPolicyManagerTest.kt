package com.luminet.android.tunnel

import org.junit.Assert.*
import org.junit.Test

class SplitTunnelPolicyManagerTest {

    @Test
    fun testEffectivePackagesAndExclusion() {
        val policy = SplitTunnelPolicy(
            mode = SplitTunnelMode.ONLY,
            packages = setOf("com.android.chrome", "org.mozilla.firefox", "com.luminet.android")
        )

        // Self package must be excluded
        val effective = policy.effectivePackages("com.luminet.android")
        assertEquals(2, effective.size)
        assertTrue(effective.contains("com.android.chrome"))
        assertTrue(effective.contains("org.mozilla.firefox"))
        assertFalse(effective.contains("com.luminet.android"))

        // Validation error check
        assertNull(policy.validationError("com.luminet.android"))

        // If only self was selected, validation error must trigger
        val selfOnly = SplitTunnelPolicy(
            mode = SplitTunnelMode.ONLY,
            packages = setOf("com.luminet.android")
        )
        assertNotNull(selfOnly.validationError("com.luminet.android"))
    }

    @Test
    fun testIsEffectivelyEverything() {
        val allPolicy = SplitTunnelPolicy(mode = SplitTunnelMode.ALL)
        assertTrue(allPolicy.isEffectivelyEverything("com.luminet.android"))

        val onlyPolicy = SplitTunnelPolicy(
            mode = SplitTunnelMode.ONLY,
            packages = setOf("com.android.chrome")
        )
        assertFalse(onlyPolicy.isEffectivelyEverything("com.luminet.android"))

        val exceptEmptyPolicy = SplitTunnelPolicy(
            mode = SplitTunnelMode.EXCEPT,
            packages = setOf("com.luminet.android") // Self is removed, leaving empty
        )
        assertTrue(exceptEmptyPolicy.isEffectivelyEverything("com.luminet.android"))
    }

    @Test
    fun testEncodeDecode() {
        val original = SplitTunnelPolicy(
            mode = SplitTunnelMode.EXCEPT,
            packages = setOf("app.a", "app.b")
        )
        val encoded = original.encode()
        val decoded = SplitTunnelPolicy.decode(encoded)

        assertEquals(original.mode, decoded.mode)
        assertEquals(original.packages, decoded.packages)
    }

    @Test
    fun testTrafficRateSmoother() {
        val smoother = TrafficRateSmoother()
        val (d1, u1) = smoother.smooth(100000, 50000)
        assertEquals(100000L, d1)
        assertEquals(50000L, u1)

        // Exponential smoothing check
        val (d2, u2) = smoother.smooth(100000, 0)
        assertEquals(100000L, d2)
        assertEquals(20000L, u2) // 50000 * 0.4 + 0 * 0.6 = 20000

        assertEquals("1.5 KB", TrafficRateSmoother.formatBytes(1536))
        assertEquals("10 MB/s", TrafficRateSmoother.formatRate(10 * 1024 * 1024))
    }
}
