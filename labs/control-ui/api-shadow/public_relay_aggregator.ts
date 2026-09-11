export interface UiRelayNode {
  nodeId: string;
  protocol: string;
  host: string;
  port: number;
  countryCode: string;
  pingMs: number;
  isAlive?: boolean;
}

export class PublicRelayAggregator {
  private relays: Map<string, UiRelayNode> = new Map();

  ingestNode(node: UiRelayNode): void {
    this.relays.set(node.nodeId, { ...node, isAlive: node.isAlive ?? true });
  }

  updateHealth(nodeId: string, pingMs: number, isAlive: boolean): boolean {
    const n = this.relays.get(nodeId);
    if (!n) return false;
    n.pingMs = pingMs;
    n.isAlive = isAlive;
    return true;
  }

  queryRelays(country?: string, proto?: string, maxResults: number = 10): UiRelayNode[] {
    const list = Array.from(this.relays.values())
      .filter(n => n.isAlive)
      .filter(n => !country || n.countryCode === country)
      .filter(n => !proto || n.protocol === proto)
      .sort((a, b) => a.pingMs - b.pingMs);

    return list.slice(0, maxResults);
  }

  totalCount(): number {
    return this.relays.size;
  }
}
