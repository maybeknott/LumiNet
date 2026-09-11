package com.luminet.android.tunnel

class MultipathDedupBuffer(
    var expectedSeq: Long = 1,
    val maxHistorySize: Int = 128
) {
    private val seenHistory = mutableSetOf<Long>()
    private val reorderQueue = sortedMapOf<Long, ByteArray>()

    fun ingest(seq: Long, data: ByteArray): List<ByteArray> {
        if (seq < expectedSeq || seenHistory.contains(seq) || reorderQueue.containsKey(seq)) {
            return emptyList()
        }

        seenHistory.add(seq)
        if (seenHistory.size > maxHistorySize) {
            seenHistory.remove(seenHistory.minOrNull())
        }

        reorderQueue[seq] = data

        val ready = mutableListOf<ByteArray>()
        while (reorderQueue.containsKey(expectedSeq)) {
            ready.add(reorderQueue.remove(expectedSeq)!!)
            expectedSeq++
        }
        return ready
    }
}
