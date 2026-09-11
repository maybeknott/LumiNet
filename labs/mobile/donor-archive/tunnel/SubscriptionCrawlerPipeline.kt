package com.luminet.android.tunnel

import java.util.Base64
import java.util.HashSet

data class CrawlSource(
    val url: String,
    val intervalSecs: Long,
    var lastCrawl: Long = 0,
    var totalHarvested: Int = 0,
    var enabled: Boolean = true
)

class SubscriptionCrawlerPipeline {
    private val sources = HashMap<String, CrawlSource>()
    private val harvested = HashSet<String>()

    fun addSource(url: String, intervalSecs: Long) {
        val interval = intervalSecs.coerceAtLeast(60)
        sources[url] = CrawlSource(url = url, intervalSecs = interval)
    }

    fun dispatchPendingSources(currentTime: Long): List<String> {
        val toCrawl = ArrayList<String>()
        for (src in sources.values) {
            if (src.enabled && (src.lastCrawl == 0L || currentTime >= src.lastCrawl + src.intervalSecs)) {
                src.lastCrawl = currentTime
                toCrawl.add(src.url)
            }
        }
        return toCrawl
    }

    fun ingestCrawlContent(sourceUrl: String, rawContent: String): Int {
        val trimmed = rawContent.trim()
        val decodedText = try {
            val decoded = Base64.getDecoder().decode(trimmed)
            String(decoded, Charsets.UTF_8)
        } catch (_: Exception) {
            trimmed
        }

        var count = 0
        for (line in decodedText.lines()) {
            val l = line.trim()
            if (l.startsWith("ss://") ||
                l.startsWith("vmess://") ||
                l.startsWith("vless://") ||
                l.startsWith("trojan://") ||
                l.startsWith("hysteria2://") ||
                l.startsWith("tuic://")
            ) {
                if (harvested.add(l)) {
                    count++
                }
            }
        }

        sources[sourceUrl]?.let {
            it.totalHarvested += count
        }

        return count
    }

    fun getHarvestedProxies(): List<String> = harvested.sorted()

    fun totalHarvestedCount(): Int = harvested.size
}
