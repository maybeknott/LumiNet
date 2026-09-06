import { MultiOutboundRouter } from './multi_outbound_router.js';
import type { OutboundPolicyDecision } from './multi_outbound_router.js';
import { ProviderFailoverWatcher } from './provider_failover_watcher.js';
import { CamouflageStreamMasquerader } from './camouflage_stream_masquerader.js';
import type { MasqueradeProbeVerdict } from './camouflage_stream_masquerader.js';
import { EdgeCdnPoolSorter } from './edge_cdn_pool_sorter.js';

export class AdaptiveOutboundCoordinator {
  public router: MultiOutboundRouter;
  public watcher: ProviderFailoverWatcher;
  public masquerader: CamouflageStreamMasquerader;
  public cdnSorter: EdgeCdnPoolSorter;
  public totalDispatched = 0;

  constructor(
    defaultPolicy: OutboundPolicyDecision = { type: 'DIRECT' },
    failoverThreshold: number = 3,
    sharedSecret: Uint8Array,
    decoyHost: string,
    maxCdnLatency: number = 300,
  ) {
    this.router = new MultiOutboundRouter(defaultPolicy);
    this.watcher = new ProviderFailoverWatcher(failoverThreshold);
    this.masquerader = new CamouflageStreamMasquerader(sharedSecret, decoyHost);
    this.cdnSorter = new EdgeCdnPoolSorter(maxCdnLatency);
  }

  routeAndPrepareOutbound(
    targetDomain: string,
    userId: Uint8Array,
  ): {
    policy: OutboundPolicyDecision;
    bestIp?: string | undefined;
    preamble: Uint8Array;
  } {
    this.totalDispatched++;
    const policy = this.router.matchTarget(targetDomain);
    const bestIp = this.cdnSorter.bestIp();
    const preamble = this.masquerader.generatePreamble(userId);
    return { policy, bestIp, preamble };
  }

  handleInboundProbe(preamble: Uint8Array): MasqueradeProbeVerdict {
    return this.masquerader.inspectInboundStream(preamble);
  }
}
