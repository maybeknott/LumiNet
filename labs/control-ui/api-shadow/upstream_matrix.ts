export interface MatrixUpstreamNode {
  id: string;
  protocol: string;
  endpoint: string;
  latencyMs: number;
  isAlive: boolean;
}

export class UpstreamMatrixUI {
  private nodes = new Map<string, MatrixUpstreamNode>();

  register(node: MatrixUpstreamNode): void {
    this.nodes.set(node.id, { ...node });
  }

  updateHealth(id: string, isAlive: boolean, latencyMs: number): void {
    const node = this.nodes.get(id);
    if (node) {
      node.isAlive = isAlive;
      node.latencyMs = latencyMs;
    }
  }

  selectBest(): MatrixUpstreamNode | null {
    const alive = Array.from(this.nodes.values()).filter((n) => n.isAlive);
    if (alive.length === 0) return null;
    alive.sort((a, b) => a.latencyMs - b.latencyMs);
    return alive[0]!;
  }
}
