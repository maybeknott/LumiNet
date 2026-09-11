export interface MeshLinkMetric {
  directRttMs: number;
  packetLoss: number;
  hops: number;
  cost: number;
}

export class MeshPeerMatrix {
  private readonly peers = new Map<string, Map<string, MeshLinkMetric>>();

  public recordLink(source: string, dest: string, rtt: number, loss: number, hops: number): void {
    const cost = rtt * 0.7 + loss * 350.0 + hops * 15.0;
    let adj = this.peers.get(source);
    if (!adj) {
      adj = new Map();
      this.peers.set(source, adj);
    }
    adj.set(dest, { directRttMs: rtt, packetLoss: loss, hops, cost });
  }

  public findBestRoute(source: string, dest: string): { nextHop: string; cost: number } | null {
    const adj = this.peers.get(source);
    if (!adj) return null;

    let bestNextHop: string | null = null;
    let minCost = Infinity;

    const direct = adj.get(dest);
    if (direct) {
      bestNextHop = dest;
      minCost = direct.cost;
    }

    for (const [intermediate, link1] of adj.entries()) {
      if (intermediate === dest) continue;
      const interMap = this.peers.get(intermediate);
      const link2 = interMap?.get(dest);
      if (link2) {
        const total = link1.cost + link2.cost;
        if (total < minCost) {
          minCost = total;
          bestNextHop = intermediate;
        }
      }
    }

    return bestNextHop ? { nextHop: bestNextHop, cost: minCost } : null;
  }
}
