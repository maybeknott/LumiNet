import { BlockCategory, DnsBlocklistEngine } from './dns_blocklist.js';
import { BlacklistVerdict, CanonicalBlacklistEngine } from './canonical_blacklist.js';
import { GeospatialPolygonRouter } from './geospatial_router.js';
import type { GeoPoint } from './geospatial_router.js';
import { FlowAnalyzerEngine } from './flow_analyzer.js';

export type FilterVerdict =
  | { type: 'blocked_dns'; category: BlockCategory }
  | { type: 'proxy_required'; ruleHit: string; egressTag: string }
  | { type: 'direct_pass_through'; egressTag: string };

export class IntelligentTrafficFilter {
  public dnsBlocklist = new DnsBlocklistEngine();
  public canonicalBlacklist = new CanonicalBlacklistEngine();
  public geoRouter: GeospatialPolygonRouter;
  public flowAnalyzer = new FlowAnalyzerEngine();
  public totalEvaluated = 0;
  public defaultEgress: string;
  constructor(defaultEgress: string) {
    this.defaultEgress = defaultEgress;
    this.geoRouter = new GeospatialPolygonRouter(defaultEgress);
  }

  evaluateTraffic(
    src: string,
    dst: string,
    domain?: string,
    userLocation?: GeoPoint,
    initialPayload: Uint8Array = new Uint8Array(0),
  ): FilterVerdict {
    this.totalEvaluated++;

    // 1. Flow telemetry
    this.flowAnalyzer.registerFlow(src, dst, initialPayload);

    // 2. DNS Blocklist
    if (domain) {
      const cat = this.dnsBlocklist.isDomainBlocked(domain);
      if (cat) {
        return { type: 'blocked_dns', category: cat };
      }
    }

    // 3. Spatial routing
    const spatialEgress = userLocation
      ? this.geoRouter.resolveEgress(userLocation).egressTag
      : this.defaultEgress;

    // 4. Blacklist rule
    if (domain) {
      const res = this.canonicalBlacklist.evaluateTarget(domain);
      if (res.verdict === BlacklistVerdict.Blocked) {
        return {
          type: 'proxy_required',
          ruleHit: res.rule,
          egressTag: 'tunnel-proxy',
        };
      }
    }

    return {
      type: 'direct_pass_through',
      egressTag: spatialEgress,
    };
  }
}
