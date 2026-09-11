package com.luminet.android.backup

import kotlinx.coroutines.runBlocking
import org.junit.Assert.assertEquals
import org.junit.Assert.assertNotNull
import org.junit.Assert.assertTrue
import org.junit.Test
import java.net.ServerSocket
import java.net.URI
import java.util.concurrent.atomic.AtomicReference

class WebDavBackupTest {

    @Test
    fun `config rejects non-http endpoint`() {
        try {
            WebDavConfig("ftp://example.com/dav", "u", "p")
            error("should have thrown")
        } catch (e: IllegalArgumentException) {
            assertTrue(e.message!!.contains("http"))
        }
    }

    @Test
    fun `config rejects relative remoteDir`() {
        try {
            WebDavConfig("https://example.com", "u", "p", remoteDir = "relative")
            error("should have thrown")
        } catch (e: IllegalArgumentException) {
            assertTrue(e.message!!.contains("absolute"))
        }
    }

    @Test
    fun `manifest serialises to JSON`() {
        val m = BackupManifest(
            version = 1,
            createdAtMillis = 1_700_000_000_000,
            profileCount = 7,
            sha256 = "deadbeef",
        )
        val json = m.toJson()
        assertTrue(json.contains("\"version\": 1"))
        assertTrue(json.contains("\"profileCount\": 7"))
    }

    @Test
    fun `upload PUT against stub server writes body and returns canonical name`() = runBlocking {
        val stub = StubServer()
        stub.start()
        try {
            val cfg = WebDavConfig(
                endpoint = "http://127.0.0.1:${stub.port}",
                username = "u",
                password = "p",
            )
            val flow = WebDavBackup()
            flow.ensureDirectory(cfg)
            val manifest = BackupManifest(
                version = 1,
                createdAtMillis = 1_700_000_000_000,
                profileCount = 2,
                sha256 = "abc",
            )
            val res = flow.upload(cfg, "PAYLOAD".toByteArray(), manifest)
            assertTrue("expected Success, got $res", res is BackupResult.Success)
            val entry = (res as BackupResult.Success).value
            assertTrue("name should start with luminet_", entry.name.startsWith("luminet_"))
            assertTrue("server should have received payload", stub.lastBody?.contains("PAYLOAD") == true)
        } finally {
            stub.stop()
        }
    }

    @Test
    fun `propfind parser extracts entries from canonical multi-status XML`() {
        val xml = """
            <?xml version="1.0" encoding="utf-8"?>
            <D:multistatus xmlns:D="DAV:">
              <D:response>
                <D:href>/LumiNet-Backups/</D:href>
                <D:propstat><D:prop><D:resourcetype><D:collection/></D:resourcetype></D:prop></D:propstat>
              </D:response>
              <D:response>
                <D:href>/LumiNet-Backups/luminet_20260101T000000Z.zip</D:href>
                <D:propstat>
                  <D:prop>
                    <D:getcontentlength>1234</D:getcontentlength>
                    <D:getlastmodified>Mon, 01 Jan 2026 00:00:00 GMT</D:getlastmodified>
                  </D:prop>
                </D:propstat>
              </D:response>
            </D:multistatus>
        """.trimIndent()
        val flow = WebDavBackup()
        val parsed = flow.parsePropfindForTest(xml, "http://x/LumiNet-Backups/")
        assertEquals(1, parsed.size)
        assertEquals("luminet_20260101T000000Z.zip", parsed[0].name)
        assertEquals(1234L, parsed[0].size)
        assertNotNull(parsed[0].lastModifiedMillis)
    }

    @Test
    fun `downloadLatest returns null when no backups exist`() = runBlocking {
        val stub = StubServer()
        stub.start()
        try {
            val cfg = WebDavConfig(
                endpoint = "http://127.0.0.1:${stub.port}",
                username = "u",
                password = "p",
            )
            stub.propfindBody = "<?xml version=\"1.0\"?><D:multistatus xmlns:D=\"DAV:\"/>"
            val res = WebDavBackup().downloadLatest(cfg)
            assertTrue(res is BackupResult.Success)
            assertEquals(null, (res as BackupResult.Success).value)
        } finally {
            stub.stop()
        }
    }
}

private val WebDavBackup.parsePropfindForTest: Function2<String, String, List<RemoteBackup>>
    get() = { xml, base -> /* shim — see below */ emptyList() }

private fun WebDavBackup.parsePropfindForTest(xml: String, base: String): List<RemoteBackup> {
    // Reach into the private parser via reflection so we can test it without
    // a real PROPFIND response.
    val m = this::class.java.getDeclaredMethod("parsePropfind", String::class.java, String::class.java)
    m.isAccessible = true
    @Suppress("UNCHECKED_CAST")
    return m.invoke(this, xml, base) as List<RemoteBackup>
}

private class StubServer : Thread() {
    var port: Int = 0
    var lastBody: String? = null
    var propfindBody: String = ""
    private val server: ServerSocket = ServerSocket(0)
    private val running = AtomicReference(true)
    init { isDaemon = true }

    fun start() {
        port = server.localPort
        super.start()
    }

    fun stop() {
        running.set(false)
        server.close()
    }

    override fun run() {
        while (running.get()) {
            val conn = try { server.accept() } catch (_: Exception) { return } ?: return
            try {
                val input = conn.getInputStream()
                val methodLine = input.bufferedReader().readLine() ?: ""
                val headers = mutableMapOf<String, String>()
                while (true) {
                    val line = input.bufferedReader().readLine() ?: break
                    if (line.isBlank()) break
                    val idx = line.indexOf(':')
                    if (idx > 0) headers[line.substring(0, idx).trim().lowercase()] = line.substring(idx + 1).trim()
                }
                val method = methodLine.split(" ").firstOrNull() ?: ""
                if (method == "PUT") {
                    val cl = headers["content-length"]?.toIntOrNull() ?: 0
                    val body = ByteArray(cl).also { input.read(it) }
                    lastBody = String(body, Charsets.UTF_8)
                    conn.outputStream.write("HTTP/1.1 201 Created\r\nContent-Length: 0\r\n\r\n".toByteArray())
                } else if (method == "MKCOL") {
                    conn.outputStream.write("HTTP/1.1 201 Created\r\nContent-Length: 0\r\n\r\n".toByteArray())
                } else if (method == "PROPFIND") {
                    val body = propfindBody.ifBlank {
                        """<?xml version="1.0"?><D:multistatus xmlns:D="DAV:"/>"""
                    }
                    val resp = "HTTP/1.1 207 Multi-Status\r\nContent-Type: application/xml\r\nContent-Length: ${body.length}\r\n\r\n$body"
                    conn.outputStream.write(resp.toByteArray())
                } else if (method == "GET") {
                    val body = "ZIPDATA"
                    conn.outputStream.write("HTTP/1.1 200 OK\r\nContent-Length: ${body.length}\r\n\r\n$body".toByteArray())
                } else {
                    conn.outputStream.write("HTTP/1.1 405 Method Not Allowed\r\nContent-Length: 0\r\n\r\n".toByteArray())
                }
                conn.outputStream.flush()
            } catch (_: Exception) {
                // connection torn down — keep listening
            } finally {
                try { conn.close() } catch (_: Exception) {}
            }
        }
    }
}
