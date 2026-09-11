package com.luminet.android.tunnel

class TcpWindowClamper(var clampedSize: Int = 4, var enabled: Boolean = true) {
    fun clampWindow(originalWindow: Int, isHandshake: Boolean): Int {
        if (!enabled) return originalWindow
        return if (isHandshake && originalWindow > clampedSize) clampedSize else originalWindow
    }

    fun isRstLegitimate(rstSeq: Long, lastAckSeq: Long, window: Long): Boolean {
        val diff = rstSeq - lastAckSeq
        val maxWin = if (window < 4096) 4096 else window
        return diff in 0..maxWin
    }
}
