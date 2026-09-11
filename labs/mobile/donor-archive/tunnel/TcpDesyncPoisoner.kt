package com.luminet.android.tunnel

enum class DesyncType {
    NONE,
    SPLIT,
    FAKE_TTL,
    DISORDER
}

data class DesyncPlan(
    val type: DesyncType,
    val parts: List<ByteArray>,
    val fakeTtlPart: ByteArray? = null
)

class TcpDesyncPoisoner {
    fun plan(data: ByteArray, type: DesyncType, splitOffset: Int = 2): DesyncPlan {
        if (data.isEmpty()) return DesyncPlan(DesyncType.NONE, emptyList())
        val offset = splitOffset.coerceIn(1, data.size - 1)

        val part1 = data.copyOfRange(0, offset)
        val part2 = data.copyOfRange(offset, data.size)

        return when (type) {
            DesyncType.SPLIT -> DesyncPlan(DesyncType.SPLIT, listOf(part1, part2))
            DesyncType.DISORDER -> DesyncPlan(DesyncType.DISORDER, listOf(part2, part1))
            DesyncType.FAKE_TTL -> DesyncPlan(
                type = DesyncType.FAKE_TTL,
                parts = listOf(part1, part2),
                fakeTtlPart = ByteArray(offset) { 0x58 }
            )
            DesyncType.NONE -> DesyncPlan(DesyncType.NONE, listOf(data))
        }
    }
}
