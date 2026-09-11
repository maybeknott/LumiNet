package com.luminet.android.tunnel

data class AmneziaObfsConfig(
    var jc: Int = 4,
    var jmin: Int = 40,
    var jmax: Int = 70,
    var s1: Int = 56,
    var s2: Int = 56,
    var h1: Long = 0x01000000L,
    var h2: Long = 0x02000000L,
    var h3: Long = 0x03000000L,
    var h4: Long = 0x04000000L
) {
    fun isValid(): Boolean {
        if (jc !in 0..128) return false
        if (jmin < 0 || jmax < jmin || jmax > 1500) return false
        if (s1 !in 0..1024 || s2 !in 0..1024) return false
        return true
    }

    fun parseLine(line: String): Boolean {
        val parts = line.split("=")
        if (parts.size != 2) return false
        val key = parts[0].trim().uppercase()
        val rawVal = parts[1].trim()

        val num = try {
            if (rawVal.startsWith("0x", ignoreCase = true)) {
                rawVal.substring(2).toLong(16)
            } else {
                rawVal.toLong()
            }
        } catch (_: Exception) {
            return false
        }

        when (key) {
            "JC" -> jc = num.toInt()
            "JMIN" -> jmin = num.toInt()
            "JMAX" -> jmax = num.toInt()
            "S1" -> s1 = num.toInt()
            "S2" -> s2 = num.toInt()
            "H1" -> h1 = num
            "H2" -> h2 = num
            "H3" -> h3 = num
            "H4" -> h4 = num
            else -> return false
        }
        return true
    }
}
