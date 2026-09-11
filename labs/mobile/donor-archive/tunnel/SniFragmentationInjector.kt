package com.luminet.android.tunnel

class SniFragmentationInjector(val decoyDomain: String = "www.microsoft.com") {
    fun splitInMiddle(payload: ByteArray): List<ByteArray> {
        if (payload.size <= 2) return listOf(payload)
        val mid = payload.size / 2
        val first = payload.copyOfRange(0, mid)
        val second = payload.copyOfRange(mid, payload.size)
        return listOf(first, second)
    }

    fun injectDecoy(realClientHello: ByteArray): List<ByteArray> {
        val decoyHeader = byteArrayOf(0x16, 0x03, 0x01, 0x00, 0x10)
        val decoy = decoyHeader + decoyDomain.toByteArray(Charsets.UTF_8)
        return listOf(decoy, realClientHello)
    }
}
