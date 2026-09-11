package com.luminet.android.tunnel

import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertTrue
import org.junit.Test
import java.net.ServerSocket
import kotlin.concurrent.thread

class SocksProbeTest {

    @Test
    fun `tunnel stage transitions correctly`() {
        val disconnected = TunnelSnapshot.DISCONNECTED
        assertEquals(TunnelStage.DISCONNECTED, disconnected.stage)
        assertTrue(disconnected.stage.isIdle)

        val connecting = TunnelSnapshot(
            stage = TunnelStage.CONNECTING,
            gateway = "127.0.0.1:1080",
            connectedAtMillis = 0L,
            message = null,
        )
        assertFalse(connecting.stage.isIdle)

        val connected = TunnelSnapshot(
            stage = TunnelStage.CONNECTED,
            gateway = "127.0.0.1:1080",
            connectedAtMillis = System.currentTimeMillis(),
            message = "Tunnel established",
        )
        assertFalse(connected.stage.isIdle)
        assertEquals(TunnelStage.CONNECTED, connected.stage)
    }

    @Test
    fun `reachable returns false when nothing is listening`() {
        // High ephemeral port that is not listening
        val port = 59123
        val result = SocksProbe.reachable(port, timeoutMs = 100)
        assertFalse(result)
    }

    @Test
    fun `reachable succeeds against mock socks5 server`() {
        val server = ServerSocket(0)
        val port = server.localPort

        thread {
            try {
                val client = server.accept()
                val input = client.getInputStream()
                val output = client.getOutputStream()

                // 1. Handshake
                val handshakeReq = ByteArray(3)
                input.read(handshakeReq)
                output.write(byteArrayOf(0x05, 0x00)) // SOCKS5 + No Auth
                output.flush()

                // 2. Connect request
                val head = ByteArray(4)
                input.read(head)
                val atyp = head[3]
                if (atyp == 0x03.toByte()) {
                    val len = input.read()
                    val domain = ByteArray(len)
                    input.read(domain)
                    val portBytes = ByteArray(2)
                    input.read(portBytes)
                }

                // Connect response: 0x05 0x00 0x00 0x01 + 0.0.0.0:0
                output.write(byteArrayOf(0x05, 0x00, 0x00, 0x01, 0, 0, 0, 0, 0, 80))
                output.flush()

                // 3. HTTP Request
                val httpReq = ByteArray(256)
                input.read(httpReq)

                // HTTP Response
                val httpResp = "HTTP/1.1 200 OK\r\nContent-Length: 2\r\n\r\nok"
                output.write(httpResp.toByteArray(Charsets.UTF_8))
                output.flush()

                client.close()
            } catch (_: Exception) {
            } finally {
                server.close()
            }
        }

        val result = SocksProbe.reachable(port, timeoutMs = 2000)
        assertTrue(result)
    }
}
