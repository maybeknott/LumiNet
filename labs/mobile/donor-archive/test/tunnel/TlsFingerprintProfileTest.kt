package com.luminet.android.tunnel

import org.junit.Assert.*
import org.junit.Test

class TlsFingerprintProfileTest {

    @Test
    fun testFromIdentifier() {
        val chrome = TlsFingerprintProfile.fromIdentifier("chrome133")
        assertEquals(TlsFingerprintProfile.CHROME_133, chrome)

        val firefox = TlsFingerprintProfile.fromIdentifier("FIREFOX120")
        assertEquals(TlsFingerprintProfile.FIREFOX_120, firefox)

        val unknown = TlsFingerprintProfile.fromIdentifier("not_a_browser")
        assertNull(unknown)
    }

    @Test
    fun testResolveLatest() {
        assertEquals(TlsFingerprintProfile.CHROME_133, TlsFingerprintProfile.resolveLatest("chrome"))
        assertEquals(TlsFingerprintProfile.FIREFOX_120, TlsFingerprintProfile.resolveLatest("firefox"))
        assertEquals(TlsFingerprintProfile.SAFARI_16, TlsFingerprintProfile.resolveLatest("safari"))
        assertEquals(TlsFingerprintProfile.EDGE_106, TlsFingerprintProfile.resolveLatest("edge"))
        assertEquals(TlsFingerprintProfile.IOS_14, TlsFingerprintProfile.resolveLatest("ios"))
        assertEquals(TlsFingerprintProfile.ANDROID_OKHTTP, TlsFingerprintProfile.resolveLatest("android"))
    }
}
