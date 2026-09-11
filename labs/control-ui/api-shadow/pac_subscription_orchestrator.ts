import { HealthTier, SubscriptionHealthClassifier } from './subscription_health_classifier.js';
import { NodePoolAggregator } from './node_pool_aggregator.js';
import { SubscriptionCrawlerPipeline } from './subscription_crawler_pipeline.js';
import { PacDiffSynchronizer } from './pac_diff_synchronizer.js';
import type { PacSyncDelta } from './pac_diff_synchronizer.js';
import { PacRuleAction, PacRuleGenerator } from './pac_rule_generator.js';

export interface OrchestratorSummary {
  totalCrawled: number;
  totalActivePool: number;
  usableTierACount: number;
  currentPacRulesCount: number;
  pacChecksum: string;
}

export class PacSubscriptionOrchestrator {
  private crawler: SubscriptionCrawlerPipeline;
  private pool: NodePoolAggregator;
  private classifier: SubscriptionHealthClassifier;
  private pacGen: PacRuleGenerator;
  private pacSync: PacDiffSynchronizer;
  public defaultProxyPort: number;

  constructor(initialDomains: string[] = [], defaultProxyPort: number = 10808) {
    this.defaultProxyPort = defaultProxyPort;
    this.pacGen = new PacRuleGenerator(PacRuleAction.Direct);
    for (const d of initialDomains) {
      this.pacGen.addRule(d, PacRuleAction.Proxy, `127.0.0.1:${defaultProxyPort}`);
    }

    this.crawler = new SubscriptionCrawlerPipeline();
    this.pool = new NodePoolAggregator();
    this.classifier = new SubscriptionHealthClassifier(10);
    this.pacSync = new PacDiffSynchronizer(initialDomains);
  }

  registerSubscriptionSource(url: string, intervalSecs: number = 3600): void {
    this.crawler.addSource(url, intervalSecs);
  }

  executeCrawlAndIngest(sourceUrl: string, rawContent: string, now: number): number {
    const count = this.crawler.ingestCrawlContent(sourceUrl, rawContent);
    const proxies = this.crawler.getHarvestedProxies();
    this.pool.ingestRawEntries(proxies, now);
    return count;
  }

  recordNodeProbe(nodeId: string, latencyMs: number, success: boolean): void {
    this.classifier.recordSample(nodeId, latencyMs, success);
    this.pool.updateHealth(nodeId, latencyMs, success);
  }

  updatePacWithUpstream(upstreamDomains: string[]): PacSyncDelta {
    const delta = this.pacSync.computeDelta(upstreamDomains);
    this.pacSync.applyDelta(delta);

    // Rebuild pacGen
    this.pacGen = new PacRuleGenerator(PacRuleAction.Direct);
    for (const domain of upstreamDomains) {
      this.pacGen.addRule(domain, PacRuleAction.Proxy, `127.0.0.1:${this.defaultProxyPort}`);
    }

    return delta;
  }

  exportActivePacScript(): string {
    return this.pacGen.generatePacScript();
  }

  getSummary(): OrchestratorSummary {
    const tierA = this.classifier.filterUsableNodes(HealthTier.TierAExcellent);
    return {
      totalCrawled: this.crawler.totalHarvestedCount(),
      totalActivePool: this.pool.rankNodes(0.0).length,
      usableTierACount: tierA.length,
      currentPacRulesCount: this.pacSync.totalRules(),
      pacChecksum: this.pacSync.currentChecksum(),
    };
  }
}
