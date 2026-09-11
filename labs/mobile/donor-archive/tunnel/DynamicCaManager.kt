// Copyright 2024-2026 LumiNet Authors. All Rights Reserved.
package com.luminet.android.tunnel

data class GeneratedCert(
    val commonName: String,
    val serialNumber: Long,
    val notBeforeMs: Long,
    val notAfterMs: Long,
    val certPayload: ByteArray
)

class DynamicCaManager(private val caName: String = "LumiNet Root CA") {
    private var serialCounter = 1000L
    private val cache = mutableMapOf<String, GeneratedCert>()
    private val lock = Any()

    fun issueOrGetCert(commonName: String, validityDurationMs: Long, nowMs: Long = System.currentTimeMillis()): GeneratedCert = synchronized(lock) {
        val existing = cache[commonName]
        if (existing != null && nowMs < existing.notAfterMs) {
            return existing
        }

        serialCounter++
        val payload = "MOCK-CERT:$caName:$commonName:$serialCounter".toByteArray()
        val cert = GeneratedCert(
            commonName = commonName,
            serialNumber = serialCounter,
            notBeforeMs = nowMs,
            notAfterMs = nowMs + validityDurationMs,
            certPayload = payload
        )
        cache[commonName] = cert
        cert
    }
}
