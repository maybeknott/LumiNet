package com.luminet.android.security

import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertTrue
import org.junit.Test

class MitmFrontingManagerTest {

    @Test
    fun `test san pattern matching exact and wildcard`() {
        assertTrue(MitmFrontingManager.matchSanPattern("www.google.com", "www.google.com"))
        assertTrue(MitmFrontingManager.matchSanPattern("WWW.GOOGLE.COM", "www.google.com"))

        assertTrue(MitmFrontingManager.matchSanPattern("api.instagram.com", "*.instagram.com"))
        assertTrue(MitmFrontingManager.matchSanPattern("r1.googlevideo.com", "*.googlevideo.com"))

        // Multi-level wildcard negative match
        assertFalse(MitmFrontingManager.matchSanPattern("nested.sub.api.instagram.com", "*.instagram.com"))
        assertFalse(MitmFrontingManager.matchSanPattern("fakeinstagram.com", "*.instagram.com"))
    }

    @Test
    fun `test ingress routing to decryption inbounds`() {
        // Direct
        val actionIr = MitmFrontingManager.routeIngress("tehran.ir")
        assertEquals(MitmAction.Direct, actionIr)

        // Video -> H1.1 port 11666
        val actionVideo = MitmFrontingManager.routeIngress("r5.sn-oxun-xx.googlevideo.com")
        assertEquals(MitmAction.RedirectToMitm(11666), actionVideo)

        // Frontable -> H2/H1.1 port 11777
        val actionFastly = MitmFrontingManager.routeIngress("reddit.com")
        assertEquals(MitmAction.RedirectToMitm(11777), actionFastly)

        val actionMeta = MitmFrontingManager.routeIngress("www.whatsapp.com")
        assertEquals(MitmAction.RedirectToMitm(11777), actionMeta)
    }

    @Test
    fun `test decrypted egress routing and repack config`() {
        // From 11666: googlevideo repacks with www.google.com and H1.1 ALPN
        val egressVideo = MitmFrontingManager.routeDecryptedEgress("r1.googlevideo.com", 11666)
        assertTrue(egressVideo is MitmAction.RepackFronted)
        val repackVideo = egressVideo as MitmAction.RepackFronted
        assertEquals("www.google.com", repackVideo.frontedSni)
        assertEquals(listOf("http/1.1"), repackVideo.alpn)

        // From 11666: non-video blocks
        val egressBlocked = MitmFrontingManager.routeDecryptedEgress("www.facebook.com", 11666)
        assertEquals(MitmAction.Block, egressBlocked)

        // From 11777: meta repacks with www.microsoft.com
        val egressMeta = MitmFrontingManager.routeDecryptedEgress("api.instagram.com", 11777)
        assertTrue(egressMeta is MitmAction.RepackFronted)
        val repackMeta = egressMeta as MitmAction.RepackFronted
        assertEquals("www.microsoft.com", repackMeta.frontedSni)
        assertEquals(listOf("h2", "http/1.1"), repackMeta.alpn)
    }
}
