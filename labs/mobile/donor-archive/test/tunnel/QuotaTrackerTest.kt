package com.luminet.android.tunnel

import org.junit.Assert.*
import org.junit.Test

class QuotaTrackerTest {

    @Test
    fun testTokenBucketLimiter() {
        val limiter = TokenBucketLimiter(10.0, 5.0)
        for (i in 0 until 5) {
            assertTrue("Token $i should be allowed", limiter.allow())
        }
        assertFalse("Token 6 should be rejected immediately", limiter.allow())
    }

    @Test
    fun testAccountQuotaTracker() {
        val tracker = AccountQuotaTracker(windowSecs = 10L, requestLimit = 2L)
        tracker.register("acc1")
        tracker.register("acc2")

        val now = 1000L
        tracker.recordOutcome("acc1", now, 100, 100, true)
        tracker.recordOutcome("acc1", now + 1, 100, 100, true)

        val best = tracker.selectBestAccount(now + 2)
        assertEquals("acc2", best)
    }
}
