package com.luminet.android.scanner

import org.json.JSONArray
import org.json.JSONObject
import java.util.Locale

/**
 * Multi-node Iran censorship prober and edge reachability assessor.
 */
object CheckHostProber {

    val DEFAULT_IRAN_NODES = listOf(
        "ir1.node.check-host.net",
        "ir2.node.check-host.net",
        "ir3.node.check-host.net",
        "ir5.node.check-host.net",
        "ir6.node.check-host.net",
        "ir7.node.check-host.net",
        "ir8.node.check-host.net"
    )

    enum class ProbeMethod {
        HTTP,
        PING,
        DNS;

        fun toParam(): String = name.lowercase(Locale.ROOT)

        companion object {
            fun fromString(s: String): ProbeMethod {
                return when (s.lowercase(Locale.ROOT).trim()) {
                    "http" -> HTTP
                    "ping" -> PING
                    "dns" -> DNS
                    else -> throw IllegalArgumentException("Unsupported probe method: $s")
                }
            }
        }
    }

    enum class CensorshipVerdict {
        CLEAN,
        FILTERED,
        HIGH_LOSS,
        DEGRADED,
        INDETERMINATE
    }

    data class NodeProbeResult(
        val node: String,
        val responsive: Boolean,
        val rttMs: Double? = null,
        val error: String? = null,
        val extraInfo: String? = null
    )

    data class CheckHostAssessment(
        val target: String,
        val method: ProbeMethod,
        val verdict: CensorshipVerdict,
        val totalNodes: Int,
        val responsiveNodes: Int,
        val blockedNodes: Int,
        val avgRttMs: Double? = null,
        val nodeResults: Map<String, NodeProbeResult>,
        val isReady: Boolean
    )

    fun buildInitiateUrl(
        target: String,
        method: ProbeMethod,
        nodes: List<String> = DEFAULT_IRAN_NODES
    ): String {
        val sb = StringBuilder("https://check-host.net/check-")
        sb.append(method.toParam())
        sb.append("?host=")
        sb.append(target)
        val selectedNodes = if (nodes.isEmpty()) DEFAULT_IRAN_NODES else nodes
        for (node in selectedNodes) {
            sb.append("&node=")
            sb.append(node.trim())
        }
        return sb.toString()
    }

    fun buildResultUrl(requestId: String): String {
        return "https://check-host.net/check-result/$requestId"
    }

    fun parseInitiateResponse(jsonStr: String): String {
        val root = JSONObject(jsonStr)
        if (root.has("error") && !root.isNull("error")) {
            throw IllegalStateException("Check-Host error: ${root.getString("error")}")
        }
        if (root.has("request_id") && !root.isNull("request_id")) {
            return root.getString("request_id")
        }
        throw IllegalStateException("No request_id found in Check-Host response")
    }

    fun evaluateVerdict(responsive: Int, total: Int, avgLossPct: Double): CensorshipVerdict {
        if (total == 0) return CensorshipVerdict.INDETERMINATE
        val ratio = responsive.toDouble() / total.toDouble()
        if (responsive == 0 || ratio <= 0.35) {
            return CensorshipVerdict.FILTERED
        }
        if (ratio >= 0.75) {
            return when {
                avgLossPct > 40.0 -> CensorshipVerdict.HIGH_LOSS
                avgLossPct > 15.0 -> CensorshipVerdict.DEGRADED
                else -> CensorshipVerdict.CLEAN
            }
        }
        return CensorshipVerdict.DEGRADED
    }

    fun parseResultResponse(
        jsonStr: String,
        target: String,
        method: ProbeMethod
    ): CheckHostAssessment {
        val root = JSONObject(jsonStr)
        val nodeResults = mutableMapOf<String, NodeProbeResult>()
        var responsiveCount = 0
        var blockedCount = 0
        var rttSum = 0.0
        var rttCount = 0
        var totalLossSum = 0.0
        var anyPending = false

        val keys = root.keys()
        while (keys.hasNext()) {
            val nodeName = keys.next()
            if (root.isNull(nodeName)) {
                anyPending = true
                continue
            }

            var responsive = false
            var nodeRtt: Double? = null
            var error: String? = null
            var extraInfo: String? = null

            when (method) {
                ProbeMethod.PING -> {
                    val outerArr = root.optJSONArray(nodeName)
                    val samples = mutableListOf<Double>()
                    if (outerArr != null) {
                        for (i in 0 until outerArr.length()) {
                            val innerArr = outerArr.optJSONArray(i) ?: continue
                            for (j in 0 until innerArr.length()) {
                                val sampleArr = innerArr.optJSONArray(j) ?: continue
                                val status = sampleArr.optString(0)
                                if (status == "OK") {
                                    val sec = sampleArr.optDouble(1, 0.0)
                                    samples.add(sec * 1000.0)
                                } else if (error == null && status.isNotEmpty()) {
                                    error = status
                                }
                            }
                        }
                    }
                    if (samples.isNotEmpty()) {
                        responsive = true
                        val avg = samples.average()
                        nodeRtt = avg
                        rttSum += avg
                        rttCount++
                        extraInfo = "samples: ${samples.size}"
                    } else {
                        totalLossSum += 100.0
                    }
                }
                ProbeMethod.HTTP -> {
                    val arr = root.optJSONArray(nodeName)
                    if (arr != null && arr.length() > 0) {
                        val firstAttempt = arr.optJSONArray(0)
                        if (firstAttempt != null) {
                            val okFlag = firstAttempt.optInt(0, 0)
                            val rttSec = firstAttempt.optDouble(1, 0.0)
                            val phrase = firstAttempt.optString(2, "")
                            val code = firstAttempt.optString(3, "")
                            val ip = firstAttempt.optString(4, "")

                            if (okFlag == 1) {
                                responsive = true
                                val ms = rttSec * 1000.0
                                nodeRtt = ms
                                rttSum += ms
                                rttCount++
                                extraInfo = "HTTP $code ($phrase) -> $ip"
                            } else {
                                error = if (phrase.isNotEmpty()) phrase else "Connection timed out or reset"
                                totalLossSum += 100.0
                            }
                        }
                    }
                }
                ProbeMethod.DNS -> {
                    val arr = root.optJSONArray(nodeName)
                    if (arr != null && arr.length() > 0) {
                        val dnsObj = arr.optJSONObject(0)
                        if (dnsObj != null && dnsObj.has("A")) {
                            val aRecords = dnsObj.optJSONArray("A")
                            if (aRecords != null && aRecords.length() > 0) {
                                responsive = true
                                val ips = mutableListOf<String>()
                                for (i in 0 until aRecords.length()) {
                                    ips.add(aRecords.optString(i))
                                }
                                extraInfo = "A: ${ips.joinToString(", ")}"
                            }
                        }
                    }
                    if (!responsive) {
                        error = "DNS resolution timed out or NXDOMAIN"
                        totalLossSum += 100.0
                    }
                }
            }

            if (responsive) {
                responsiveCount++
            } else {
                blockedCount++
            }

            nodeResults[nodeName] = NodeProbeResult(
                node = nodeName,
                responsive = responsive,
                rttMs = nodeRtt,
                error = error,
                extraInfo = extraInfo
            )
        }

        val evaluated = responsiveCount + blockedCount
        val avgLoss = if (evaluated > 0) totalLossSum / evaluated.toDouble() else 0.0
        val avgRtt = if (rttCount > 0) rttSum / rttCount.toDouble() else null
        val verdict = evaluateVerdict(responsiveCount, evaluated, avgLoss)

        return CheckHostAssessment(
            target = target,
            method = method,
            verdict = verdict,
            totalNodes = evaluated,
            responsiveNodes = responsiveCount,
            blockedNodes = blockedCount,
            avgRttMs = avgRtt,
            nodeResults = nodeResults,
            isReady = !anyPending && evaluated > 0
        )
    }
}
