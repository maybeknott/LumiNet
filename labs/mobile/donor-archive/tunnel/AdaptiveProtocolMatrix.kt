package com.luminet.android.tunnel

data class AndroidTransportPosture(
    val recommendedProtocol: String,
    val activeBackend: AndroidBackendEngine,
    val windowClampSize: Int,
    val mitigationStrategy: String
)

class AdaptiveProtocolMatrix {
    val backendController = DualBackendController()
    val windowClamper = TcpWindowClamper(2)
    val decoyInjector = SniFragmentationInjector("www.bing.com")

    fun adapt(anomaly: AndroidCensorshipAnomaly): AndroidTransportPosture {
        return when (anomaly) {
            AndroidCensorshipAnomaly.SNI_RESET -> {
                windowClamper.clampedSize = 2
                AndroidTransportPosture(
                    "Trojan-SNI-Fragment",
                    backendController.selectEngine(),
                    2,
                    "SNI fragmentation & window clamping to 2 bytes"
                )
            }
            AndroidCensorshipAnomaly.UDP_BLACKHOLE -> {
                backendController.recordMetrics(AndroidBackendEngine.KCP_RAW_SOCKET, 999, 1.0f, false)
                backendController.recordMetrics(AndroidBackendEngine.KCP_RAW_SOCKET, 999, 1.0f, false)
                backendController.recordMetrics(AndroidBackendEngine.KCP_RAW_SOCKET, 999, 1.0f, false)
                AndroidTransportPosture(
                    "VLESS-Reality",
                    backendController.selectEngine(),
                    windowClamper.clampedSize,
                    "Demoted UDP/KCP backend, transitioned to VLESS-Reality TCP"
                )
            }
            AndroidCensorshipAnomaly.TCP_RST_INJECTION -> {
                AndroidTransportPosture(
                    "Trojan-SNI-Fragment",
                    AndroidBackendEngine.VIOLATED_TCP_QUIC,
                    4,
                    "Activated Violated TCP/QUIC injection with RST poison filtering"
                )
            }
            else -> {
                AndroidTransportPosture(
                    "Hysteria2",
                    backendController.selectEngine(),
                    65535,
                    "Standard baseline transport maintained"
                )
            }
        }
    }
}
