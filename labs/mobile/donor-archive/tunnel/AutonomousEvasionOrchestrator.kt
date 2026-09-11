package com.luminet.android.tunnel

enum class AndroidEvasionMode {
    STANDARD,
    SPLIT,
    FAKE_TTL,
    DISORDER
}

class AutonomousEvasionOrchestrator(
    val rstThreshold: Int = 3
) {
    var mode: AndroidEvasionMode = AndroidEvasionMode.STANDARD
        private set
    private var rstCount = 0

    fun recordTcpReset(): AndroidEvasionMode {
        rstCount++
        if (rstCount >= rstThreshold) {
            mode = when (mode) {
                AndroidEvasionMode.STANDARD -> AndroidEvasionMode.SPLIT
                AndroidEvasionMode.SPLIT -> AndroidEvasionMode.FAKE_TTL
                AndroidEvasionMode.FAKE_TTL -> AndroidEvasionMode.DISORDER
                AndroidEvasionMode.DISORDER -> AndroidEvasionMode.STANDARD
            }
            rstCount = 0
        }
        return mode
    }

    fun reset() {
        mode = AndroidEvasionMode.STANDARD
        rstCount = 0
    }
}
