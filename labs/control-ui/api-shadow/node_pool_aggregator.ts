export interface AggregatedNode {
  id: string;
  protocol: string;
  host: string;
  port: number;
  score: number;
  latencyMs: number;
  successCount: number;
  failureCount: number;
  tags: string[];
  lastSeen: number;
}

export class NodePoolAggregator {
  private nodes = new Map<string, AggregatedNode>();

  ingestRawEntries(entries: string[], timestamp: number): number {
    let count = 0;
    for (const raw of entries) {
      const node = this.parseRawLine(raw, timestamp);
      if (node) {
        const key = `${node.protocol}:${node.host}:${node.port}`;
        const existing = this.nodes.get(key);
        if (existing) {
          existing.lastSeen = timestamp;
          for (const tag of node.tags) {
            if (!existing.tags.includes(tag)) {
              existing.tags.push(tag);
            }
          }
        } else {
          this.nodes.set(key, node);
        }
        count++;
      }
    }
    return count;
  }

  updateHealth(id: string, latencyMs: number, success: boolean): boolean {
    const node = this.nodes.get(id);
    if (!node) return false;

    if (success) {
      node.successCount++;
      node.latencyMs = Math.floor((node.latencyMs * 3 + latencyMs) / 4);
      const latScore = Math.min(100.0, 1000.0 / Math.max(10, node.latencyMs));
      const rel = node.successCount / (node.successCount + node.failureCount);
      node.score = latScore * 0.4 + rel * 60.0;
    } else {
      node.failureCount++;
      const rel = node.successCount / (node.successCount + node.failureCount);
      node.score = Math.min(node.score, rel * 60.0);
    }
    return true;
  }

  totalNodes(): number {
    return this.nodes.size;
  }

  rankNodes(minScore: number = 0): AggregatedNode[] {
    return Array.from(this.nodes.values())
      .filter((n) => n.score >= minScore)
      .sort((a, b) => b.score - a.score);
  }

  private parseRawLine(raw: string, timestamp: number): AggregatedNode | null {
    const trimmed = raw.trim();
    if (!trimmed || trimmed.startsWith('#')) return null;

    const idx = trimmed.indexOf('://');
    if (idx === -1) return null;

    const protocol = trimmed.substring(0, idx).toLowerCase();
    const rem = trimmed.substring(idx + 3);

    const parts = rem.split('@');
    const hostPort = parts.length > 1 ? parts[1] : parts[0];
    const hostSplit = hostPort!.split(':');
    if (hostSplit.length < 2) return null;

    const host = hostSplit[0]!;
    const portStr = hostSplit[1]!.split(/[/ ?#]/)[0]!;
    const port = parseInt(portStr, 10) || 443;

    return {
      id: `${protocol}:${host}:${port}`,
      protocol,
      host,
      port,
      score: 50.0,
      latencyMs: 200,
      successCount: 1,
      failureCount: 0,
      tags: ['public_pool'],
      lastSeen: timestamp,
    };
  }
}
