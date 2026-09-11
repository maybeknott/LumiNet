export interface UiDiversityNode {
  nodeId: string;
  asn: number;
  countryCode: string;
  latencyMs: number;
}

export interface UiDiversityMetrics {
  totalNodes: number;
  uniqueAsns: number;
  uniqueCountries: number;
  diversityScore: number;
}

export class NodeDiversitySampler {
  private nodes: Map<string, UiDiversityNode> = new Map();

  addNode(node: UiDiversityNode): void {
    this.nodes.set(node.nodeId, node);
  }

  computeMetrics(): UiDiversityMetrics {
    if (this.nodes.size === 0) {
      return { totalNodes: 0, uniqueAsns: 0, uniqueCountries: 0, diversityScore: 0 };
    }

    const asnCounts = new Map<number, number>();
    const countryCounts = new Map<string, number>();

    for (const n of this.nodes.values()) {
      asnCounts.set(n.asn, (asnCounts.get(n.asn) ?? 0) + 1);
      countryCounts.set(n.countryCode, (countryCounts.get(n.countryCode) ?? 0) + 1);
    }

    const total = this.nodes.size;
    let entropy = 0;
    for (const count of asnCounts.values()) {
      const p = count / total;
      entropy -= p * Math.log2(p);
    }

    const maxEntropy = Math.max(1.0, Math.log2(total));
    const normEntropy = Math.min(1.0, entropy / maxEntropy);
    const countryFactor = Math.min(1.0, countryCounts.size / total);
    const score = Math.min(100.0, normEntropy * 60.0 + countryFactor * 40.0);

    return {
      totalNodes: total,
      uniqueAsns: asnCounts.size,
      uniqueCountries: countryCounts.size,
      diversityScore: score,
    };
  }

  sampleDiverseSubset(maxNodes: number): string[] {
    const list = Array.from(this.nodes.values()).sort((a, b) => a.latencyMs - b.latencyMs);
    const asnSeen = new Set<number>();
    const sampled: string[] = [];

    // Pass 1: 1 per ASN
    for (const n of list) {
      if (sampled.length >= maxNodes) break;
      if (!asnSeen.has(n.asn)) {
        asnSeen.add(n.asn);
        sampled.push(n.nodeId);
      }
    }

    // Pass 2: fill remaining by latency
    for (const n of list) {
      if (sampled.length >= maxNodes) break;
      if (!sampled.includes(n.nodeId)) {
        sampled.push(n.nodeId);
      }
    }

    return sampled;
  }
}
