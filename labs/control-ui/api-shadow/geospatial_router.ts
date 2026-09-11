export interface GeoPoint {
  latitude: number;
  longitude: number;
}

export interface GeoBoundingBox {
  minLat: number;
  maxLat: number;
  minLon: number;
  maxLon: number;
}

export class GeoFencedRegion {
  public bbox: GeoBoundingBox;
  public regionCode: string;
  public regionName: string;
  public vertices: GeoPoint[];
  public egressTag: string;
  constructor(regionCode: string, regionName: string, vertices: GeoPoint[], egressTag: string) {
    this.regionCode = regionCode;
    this.regionName = regionName;
    this.vertices = vertices;
    this.egressTag = egressTag;
    let minLat = Infinity;
    let maxLat = -Infinity;
    let minLon = Infinity;
    let maxLon = -Infinity;
    for (const v of vertices) {
      minLat = Math.min(minLat, v.latitude);
      maxLat = Math.max(maxLat, v.latitude);
      minLon = Math.min(minLon, v.longitude);
      maxLon = Math.max(maxLon, v.longitude);
    }
    this.bbox = { minLat, maxLat, minLon, maxLon };
  }

  containsPoint(p: GeoPoint): boolean {
    if (
      p.latitude < this.bbox.minLat ||
      p.latitude > this.bbox.maxLat ||
      p.longitude < this.bbox.minLon ||
      p.longitude > this.bbox.maxLon
    ) {
      return false;
    }

    const n = this.vertices.length;
    if (n < 3) return false;

    let inside = false;
    let j = n - 1;
    for (let i = 0; i < n; i++) {
      const vi = this.vertices[i]!;
      const vj = this.vertices[j]!;

      const intersect =
        vi.latitude > p.latitude !== vj.latitude > p.latitude &&
        p.longitude <
          ((vj.longitude - vi.longitude) * (p.latitude - vi.latitude)) /
            (vj.latitude - vi.latitude) +
            vi.longitude;

      if (intersect) inside = !inside;
      j = i;
    }
    return inside;
  }
}

export class GeospatialPolygonRouter {
  private regions: GeoFencedRegion[] = [];
  public defaultEgress: string;
  constructor(defaultEgress: string) {
    this.defaultEgress = defaultEgress;
  }

  addRegion(region: GeoFencedRegion): void {
    this.regions.push(region);
  }

  resolveEgress(p: GeoPoint): { egressTag: string; regionCode?: string } {
    for (const r of this.regions) {
      if (r.containsPoint(p)) {
        return { egressTag: r.egressTag, regionCode: String(r.regionCode) };
      }
    }
    return { egressTag: this.defaultEgress };
  }
}
