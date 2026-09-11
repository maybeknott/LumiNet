export interface ScrapedNodeInfo {
  host: string;
  port: number;
  protocol: string;
  source: string;
  pingMs: number;
  isAlive: boolean;
}

export class NodeIngestDeduplicator {
  private seenEndpoints = new Set<string>();
  private uniqueNodes: ScrapedNodeInfo[] = [];
  private sourceStats = new Map<string, number>();

  ingestNode(node: ScrapedNodeInfo): boolean {
    const key = `${node.host.trim().toLowerCase()}:${node.port}:${node.protocol.trim().toLowerCase()}`;
    if (this.seenEndpoints.has(key)) {
      return false;
    }
    this.seenEndpoints.add(key);
    this.sourceStats.set(node.source, (this.sourceStats.get(node.source) || 0) + 1);
    this.uniqueNodes.push(node);
    return true;
  }

  getRankedNodes(): ScrapedNodeInfo[] {
    return this.uniqueNodes
      .filter((n) => n.isAlive)
      .sort((a, b) => a.pingMs - b.pingMs);
  }

  totalUnique(): number {
    return this.uniqueNodes.length;
  }

  countForSource(source: string): number {
    return this.sourceStats.get(source) || 0;
  }
}
