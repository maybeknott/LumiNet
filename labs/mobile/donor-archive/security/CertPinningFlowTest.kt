package com.luminet.android.security

import kotlinx.coroutines.runBlocking
import org.junit.Assert.assertEquals
import org.junit.Assert.assertTrue
import org.junit.Assert.assertNotEquals
import org.junit.Test
import java.security.cert.X509Certificate
import java.util.Date
import javax.security.auth.x500.X500Principal

class CertPinningFlowTest {

    private val flow = CertPinningFlow()

    @Test
    fun `pinned cert is accepted`() = runBlocking {
        val cert = fakeCert("hello".toByteArray())
        val pin = flow.pinCertificate(cert)
        val cfg = flow.pinningConfigFor("p1", pin)
        val session = fakeSession(listOf(cert))
        val result = flow.verifyPinnedCert(session, cfg)
        assertTrue("expected Ok, got $result", result is PinResult.Ok)
    }

    @Test
    fun `unpinned cert is rejected with Mismatch`() = runBlocking {
        val cert = fakeCert("hello".toByteArray())
        val other = fakeCert("world".toByteArray())
        val pin = flow.pinCertificate(cert)
        val cfg = flow.pinningConfigFor("p1", pin)
        val session = fakeSession(listOf(other))
        val result = flow.verifyPinnedCert(session, cfg)
        assertTrue("expected Mismatch, got $result", result is PinResult.Mismatch)
    }

    @Test
    fun `backup pin is accepted`() = runBlocking {
        val cert = fakeCert("primary".toByteArray())
        val backup = fakeCert("backup".toByteArray())
        val cfg = flow.pinningConfigFor(
            "p1",
            flow.pinCertificate(cert),
            backups = listOf(flow.pinCertificate(backup)),
        )
        val session = fakeSession(listOf(backup))
        val result = flow.verifyPinnedCert(session, cfg)
        assertTrue(result is PinResult.Ok)
    }

    @Test
    fun `disabled policy short-circuits`() = runBlocking {
        val cert = fakeCert("x".toByteArray())
        val cfg = PinningConfig("p1", listOf("0".repeat(64)), policy = "off")
        val result = flow.verifyPinnedCert(fakeSession(listOf(cert)), cfg)
        assertEquals(PinResult.Disabled, result)
    }

    @Test
    fun `expired config is rejected`() = runBlocking {
        val cert = fakeCert("x".toByteArray())
        val pin = flow.pinCertificate(cert)
        val cfg = PinningConfig(
            profileId = "p1",
            leafPins = listOf(pin.spkiSha256),
            expiresAtMillis = 1L, // long past
        )
        val result = flow.verifyPinnedCert(fakeSession(listOf(cert)), cfg)
        assertEquals(PinResult.Expired, result)
    }

    @Test
    fun `v2rayNgPin returns the SPKI hash`() = runBlocking {
        val cert = fakeCert("payload".toByteArray())
        val pin = flow.pinCertificate(cert)
        // SPKI hash is what v2rayNG expects in certSha256.
        assertEquals(pin.spkiSha256, pin.v2rayNgPin())
    }

    @Test
    fun `config serialises to JSON`() {
        val cfg = PinningConfig(profileId = "p1", leafPins = listOf("a".repeat(64)))
        val json = cfg.toV2rayNgConfigJson()
        assertTrue(json.contains("\"profileId\": \"p1\""))
        assertTrue(json.contains("\"policy\": \"strict\""))
    }

    @Test(expected = IllegalArgumentException::class)
    fun `non-hex pin is rejected`() {
        PinningConfig("p1", leafPins = listOf("Z".repeat(64)))
    }

    @Test(expected = IllegalArgumentException::class)
    fun `empty leafPins is rejected`() {
        PinningConfig("p1", leafPins = emptyList())
    }

    @Test
    fun `same content yields same SPKI hash`() = runBlocking {
        val a = flow.pinCertificate(fakeCert("k".repeat(32)))
        val b = flow.pinCertificate(fakeCert("k".repeat(32)))
        assertEquals(a.spkiSha256, b.spkiSha256)
    }

    @Test
    fun `different content yields different SPKI hash`() = runBlocking {
        val a = flow.pinCertificate(fakeCert("alpha".toByteArray()))
        val b = flow.pinCertificate(fakeCert("beta".toByteArray()))
        assertNotEquals(a.spkiSha256, b.spkiSha256)
    }

    private fun fakeCert(payload: ByteArray): X509Certificate = object : X509Certificate() {
        override fun getEncoded(): ByteArray = payload
        override fun getPublicKey(): java.security.PublicKey =
            java.security.KeyFactory.getInstance("RSA")
                .generatePublic(java.security.spec.X509EncodedKeySpec(payload + payload))
        override fun getSubjectX500Principal(): X500Principal =
            X500Principal("CN=test")
        override fun getIssuerX500Principal(): X500Principal =
            X500Principal("CN=test")
        override fun getNotAfter(): Date = Date(System.currentTimeMillis() + 86_400_000)
        // The remainder of the X509Certificate API is unused by the flow.
        override fun getType(): String = "X.509"
        override fun getVersion(): Int = 3
        override fun getSerialNumber(): java.math.BigInteger = java.math.BigInteger.ONE
        override fun getIssuerDN(): java.security.Principal = getIssuerX500Principal()
        override fun getSubjectDN(): java.security.Principal = getSubjectX500Principal()
        override fun getNotBefore(): Date = Date()
        override fun getSigAlgName(): String = "SHA256withRSA"
        override fun getSigAlgOID(): String = "1.2.840.113549.1.1.11"
        override fun getSigAlgParams(): ByteArray? = null
        override fun checkValidity() {}
        override fun checkValidity(date: Date) {}
        override fun getSignature(): ByteArray = ByteArray(0)
        override fun getTBSCertificate(): ByteArray = payload
        override fun getBasicConstraints(): Int = -1
        override fun getKeyUsage(): BooleanArray? = null
        override fun getExtendedKeyUsage(): List<String>? = null
        override fun getSubjectUniqueID(): BooleanArray? = null
        override fun getIssuerUniqueID(): BooleanArray? = null
        override fun getCriticalExtensionOIDs(): Set<String>? = null
        override fun getNonCriticalExtensionOIDs(): Set<String>? = null
        override fun hasUnsupportedCriticalExtension(): Boolean = false
        override fun verify(key: java.security.PublicKey) {}
        override fun verify(key: java.security.PublicKey, sigProvider: String) {}
        override fun toString(): String = "FakeCert"
    }

    private fun fakeSession(certs: List<X509Certificate>): SSLSessionShim =
        SSLSessionShim(certs)
}

/** Minimal SSLSession shim that only returns peer certificates. */
class SSLSessionShim(private val certs: List<X509Certificate>) : javax.net.ssl.SSLSession {
    override fun getPeerCertificates(): Array<java.security.cert.Certificate> = certs.toTypedArray()
    override fun getPeerCertificateChain(): Array<javax.net.ssl.SSLSession?> = arrayOf(this)
    // The rest of SSLSession is not exercised by the flow.
    override fun getId(): String = "test"
    override fun getSessionContext(): javax.net.ssl.SSLSessionContext? = null
    override fun getCreationTime(): Long = 0
    override fun getLastAccessedTime(): Long = 0
    override fun invalidate() {}
    override fun isValid(): Boolean = true
    override fun putValue(name: String, value: Any?) {}
    override fun getValue(name: String): Any? = null
    override fun removeValue(name: String) {}
    override fun getValueNames(): Array<String> = emptyArray()
    override fun getCipherSuite(): String = "TLS_AES_256_GCM_SHA384"
    override fun getProtocol(): String = "TLSv1.3"
    override fun getPeerHost(): String = "test"
    override fun getPeerPort(): Int = 443
    override fun getLocalCertificates(): Array<java.security.cert.Certificate> = emptyArray()
    override fun getLocalPrincipal(): java.security.Principal? = null
    override fun getPeerPrincipal(): java.security.Principal? = null
    override fun getPacketBufferSize(): Int = 16_384
    override fun getApplicationBufferSize(): Int = 16_384
}
