export interface OutboundCandidate {
  nodeId: string;
  protocol: string;
  endpoint: string;
  ewmaLatencyMs: number;
  totalProbes: number;
}

export class LatencyRaceSelector {
  private readonly nodes = new Map<string, OutboundCandidate>();

  public registerNode(id: string, protocol: string, endpoint: string): void {
    this.nodes.set(id, {
      nodeId: id,
      protocol,
      endpoint,
      ewmaLatencyMs: 0,
      totalProbes: 0
    });
  }

  public recordProbe(id: string, latencyMs: number): void {
    const node = this.nodes.get(id);
    if (!node) return;
    node.totalProbes++;
    node.ewmaLatencyMs = node.ewmaLatencyMs === 0 ? latencyMs : 0.7 * node.ewmaLatencyMs + 0.3 * latencyMs;
  }

  public selectFastest(): OutboundCandidate | null {
    const probed = Array.from(this.nodes.values()).filter(n => n.ewmaLatencyMs > 0);
    if (probed.length === 0) return null;
    return probed.reduce((best, cur) => cur.ewmaLatencyMs < best.ewmaLatencyMs ? cur : best);
  }
}
