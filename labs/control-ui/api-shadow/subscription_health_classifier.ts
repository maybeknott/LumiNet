export const HealthTier = {
  TierFDead: 0,
  TierCDegraded: 1,
  TierBGood: 2,
  TierAExcellent: 3,
} as const;
export type HealthTier = (typeof HealthTier)[keyof typeof HealthTier];

export interface NodeHealthReport {
  nodeId: string;
  tier: HealthTier;
  avgRttMs: number;
  jitterMs: number;
  packetLoss: number;
  totalProbes: number;
}

interface NodeProbeStats {
  samples: number[];
  failures: number;
  total: number;
}

export class SubscriptionHealthClassifier {
  private nodes: Map<string, NodeProbeStats> = new Map();
  public maxSamplesPerNode: number;

  constructor(maxSamplesPerNode: number = 10) {
    this.maxSamplesPerNode = Math.max(5, maxSamplesPerNode);
  }

  recordSample(nodeId: string, rttMs: number, success: boolean): void {
    let stats = this.nodes.get(nodeId);
    if (!stats) {
      stats = { samples: [], failures: 0, total: 0 };
      this.nodes.set(nodeId, stats);
    }

    stats.total += 1;
    if (success) {
      stats.samples.push(rttMs);
      if (stats.samples.length > this.maxSamplesPerNode) {
        stats.samples.shift();
      }
    } else {
      stats.failures += 1;
    }
  }

  classifyNode(nodeId: string): HealthTier {
    const stats = this.nodes.get(nodeId);
    if (!stats || stats.samples.length === 0) {
      return HealthTier.TierFDead;
    }

    const loss = stats.failures / stats.total;
    const avgRtt = stats.samples.reduce((a, b) => a + b, 0) / stats.samples.length;

    if (loss <= 0.05 && avgRtt <= 80) {
      return HealthTier.TierAExcellent;
    } else if (loss <= 0.15 && avgRtt <= 200) {
      return HealthTier.TierBGood;
    } else if (loss <= 0.4 && avgRtt <= 600) {
      return HealthTier.TierCDegraded;
    } else {
      return HealthTier.TierFDead;
    }
  }

  generateReport(nodeId: string): NodeHealthReport | null {
    const stats = this.nodes.get(nodeId);
    if (!stats) return null;

    if (stats.samples.length === 0) {
      return {
        nodeId,
        tier: HealthTier.TierFDead,
        avgRttMs: 0,
        jitterMs: 0,
        packetLoss: 1.0,
        totalProbes: stats.total,
      };
    }

    const avgRtt = Math.round(stats.samples.reduce((a, b) => a + b, 0) / stats.samples.length);
    let jitter = 0;
    for (let i = 0; i < stats.samples.length - 1; i++) {
      jitter += Math.abs(stats.samples[i]! - stats.samples[i + 1]!);
    }
    if (stats.samples.length > 1) {
      jitter = Math.round(jitter / (stats.samples.length - 1));
    }

    const loss = stats.failures / stats.total;
    const tier = this.classifyNode(nodeId);

    return {
      nodeId,
      tier,
      avgRttMs: avgRtt,
      jitterMs: jitter,
      packetLoss: loss,
      totalProbes: stats.total,
    };
  }

  filterUsableNodes(minTier: HealthTier): string[] {
    const usable: string[] = [];
    for (const id of this.nodes.keys()) {
      if (this.classifyNode(id) >= minTier) {
        usable.push(id);
      }
    }
    return usable;
  }
}
