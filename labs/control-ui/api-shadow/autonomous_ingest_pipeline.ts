import { SubscriptionNodeExtractor } from './subscription_node_extractor.js';
import { NodeIngestDeduplicator } from './node_ingest_deduplicator.js';
import type { ScrapedNodeInfo } from './node_ingest_deduplicator.js';
import { EnhancedGeoIpLookup } from './enhanced_geoip_lookup.js';
import { CompositeRuleCompiler } from './composite_rule_compiler.js';
import { PolicyRulesetRouter } from './policy_ruleset_router.js';
import type { PolicyVerdict } from './policy_ruleset_router.js';

export class AutonomousIngestPipeline {
  public deduplicator = new NodeIngestDeduplicator();
  public geoip = new EnhancedGeoIpLookup();
  public ruleCompiler = new CompositeRuleCompiler();
  public policyRouter: PolicyRulesetRouter;
  public totalIngested = 0;

  constructor(defaultPolicy: PolicyVerdict = 'DIRECT') {
    this.policyRouter = new PolicyRulesetRouter(defaultPolicy);
  }

  ingestSubscriptionManifest(sourceName: string, b64Manifest: string): number {
    const extractor = new SubscriptionNodeExtractor();
    const nodes = extractor.decodeSubscription(b64Manifest);
    let added = 0;

    for (const node of nodes) {
      const scraped: ScrapedNodeInfo = {
        host: node.address,
        port: node.port,
        protocol: node.nodeType,
        source: sourceName,
        pingMs: 100,
        isAlive: true,
      };
      if (this.deduplicator.ingestNode(scraped)) {
        added++;
      }
    }
    this.totalIngested += added;
    return added;
  }

  evaluateEgress(targetDomain: string, destIpStr?: string): PolicyVerdict {
    // 1. Composite rule check
    const act = this.ruleCompiler.evaluateDomain(targetDomain);
    if (act) {
      switch (act) {
        case 'DIRECT':
          return 'DIRECT';
        case 'PROXY':
          return 'PROXY';
        case 'REJECT':
          return 'REJECT';
      }
    }

    // 2. IP GeoIP check
    if (destIpStr) {
      const ipAct = this.ruleCompiler.evaluateIp(destIpStr);
      if (ipAct) {
        switch (ipAct) {
          case 'DIRECT':
            return 'DIRECT';
          case 'PROXY':
            return 'PROXY';
          case 'REJECT':
            return 'REJECT';
        }
      }
      if (this.geoip.lookup(destIpStr) === 'CN') {
        return 'DIRECT';
      }
    }

    // 3. Fallback to policy router
    return this.policyRouter.resolveDomain(targetDomain);
  }
}
