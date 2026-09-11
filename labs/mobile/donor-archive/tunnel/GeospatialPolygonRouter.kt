package com.luminet.android.tunnel

data class AndroidGeoPoint(
    val latitude: Double,
    val longitude: Double
)

data class AndroidBoundingBox(
    val minLat: Double,
    val maxLat: Double,
    val minLon: Double,
    val maxLon: Double
) {
    fun contains(p: AndroidGeoPoint): Boolean {
        return p.latitude in minLat..maxLat && p.longitude in minLon..maxLon
    }
}

class AndroidGeoRegion(
    val regionCode: String,
    val regionName: String,
    val vertices: List<AndroidGeoPoint>,
    val egressTag: String
) {
    val bbox: AndroidBoundingBox

    init {
        var minLat = Double.MAX_VALUE
        var maxLat = -Double.MAX_VALUE
        var minLon = Double.MAX_VALUE
        var maxLon = -Double.MAX_VALUE
        for (v in vertices) {
            minLat = minOf(minLat, v.latitude)
            maxLat = maxOf(maxLat, v.latitude)
            minLon = minOf(minLon, v.longitude)
            maxLon = maxOf(maxLon, v.longitude)
        }
        bbox = AndroidBoundingBox(minLat, maxLat, minLon, maxLon)
    }

    fun containsPoint(p: AndroidGeoPoint): Boolean {
        if (!bbox.contains(p)) return false
        val n = vertices.size
        if (n < 3) return false

        var inside = false
        var j = n - 1
        for (i in 0 until n) {
            val vi = vertices[i]
            val vj = vertices[j]
            val intersect = ((vi.latitude > p.latitude) != (vj.latitude > p.latitude)) &&
                    (p.longitude < (vj.longitude - vi.longitude) * (p.latitude - vi.latitude) / (vj.latitude - vi.latitude) + vi.longitude)
            if (intersect) inside = !inside
            j = i
        }
        return inside
    }
}

class GeospatialPolygonRouter(
    val defaultEgress: String
) {
    private val regions = mutableListOf<AndroidGeoRegion>()

    fun addRegion(region: AndroidGeoRegion) {
        regions.add(region)
    }

    fun resolveEgress(point: AndroidGeoPoint): Pair<String, String?> {
        for (r in regions) {
            if (r.containsPoint(point)) {
                return Pair(r.egressTag, r.regionCode)
            }
        }
        return Pair(defaultEgress, null)
    }
}
