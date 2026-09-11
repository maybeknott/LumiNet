package com.luminet.android.tunnel

enum class AndroidProbeCategory {
    HOST_HEADER, PATH_KEYWORD, SNI_PATTERN, DNS_QUERY_NAME
}

data class AndroidTriggerProbeSpec(
    val category: AndroidProbeCategory,
    val payloadString: String,
    val expectedBlockMechanism: String
)

class CensorshipTriggerGenerator {
    private val triggers = mutableListOf<AndroidTriggerProbeSpec>()

    init {
        populateDefaultTriggers()
    }

    private fun populateDefaultTriggers() {
        triggers.add(
            AndroidTriggerProbeSpec(
                category = AndroidProbeCategory.SNI_PATTERN,
                payloadString = "zh.wikipedia.org",
                expectedBlockMechanism = "SNI_RST"
            )
        )
        triggers.add(
            AndroidTriggerProbeSpec(
                category = AndroidProbeCategory.HOST_HEADER,
                payloadString = "Host: epochtimes.com\r\n",
                expectedBlockMechanism = "HTTP_RESET"
            )
        )
        triggers.add(
            AndroidTriggerProbeSpec(
                category = AndroidProbeCategory.DNS_QUERY_NAME,
                payloadString = "www.youtube.com",
                expectedBlockMechanism = "DNS_POISON"
            )
        )
        triggers.add(
            AndroidTriggerProbeSpec(
                category = AndroidProbeCategory.PATH_KEYWORD,
                payloadString = "/search?q=falun",
                expectedBlockMechanism = "HTTP_KEYWORD_RST"
            )
        )
    }

    fun addCustomTrigger(category: AndroidProbeCategory, payload: String, mechanism: String) {
        triggers.add(
            AndroidTriggerProbeSpec(
                category = category,
                payloadString = payload,
                expectedBlockMechanism = mechanism
            )
        )
    }

    fun generateHttpProbe(targetHost: String, path: String): ByteArray {
        val req = "GET $path HTTP/1.1\r\nHost: $targetHost\r\nUser-Agent: LumiProbe/1.0\r\nConnection: close\r\n\r\n"
        return req.toByteArray(Charsets.UTF_8)
    }

    fun getProbesByCategory(category: AndroidProbeCategory): List<AndroidTriggerProbeSpec> {
        return triggers.filter { it.category == category }
    }

    fun totalProbes(): Int = triggers.size
}
