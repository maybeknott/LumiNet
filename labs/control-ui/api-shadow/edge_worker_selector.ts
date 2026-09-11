/**
 * Edge Worker Endpoint Selector and Latency Rater
 */
export interface WorkerEndpoint {
  domain: string;
  cleanIp: string;
  port: number;
  latencyMs: number;
  packetLossPct: number;
}

export class EdgeWorkerSelector {
  private endpoints: WorkerEndpoint[] = [];

  score(ep: WorkerEndpoint): number {
    return ep.latencyMs + ep.packetLossPct * 150.0;
  }

  addOrUpdate(
    domain: string,
    cleanIp: string,
    port: number,
    latencyMs: number,
    loss: number,
  ): void {
    const found = this.endpoints.find((e) => e.domain === domain && e.cleanIp === cleanIp);
    if (found) {
      found.latencyMs = latencyMs;
      found.packetLossPct = loss;
      found.port = port;
    } else {
      this.endpoints.push({
        domain,
        cleanIp,
        port,
        latencyMs,
        packetLossPct: loss,
      });
    }
  }

  selectBest(): WorkerEndpoint | null {
    if (this.endpoints.length === 0) return null;
    return [...this.endpoints].sort((a, b) => this.score(a) - this.score(b))[0]!;
  }

  synthesizeVlessUri(ep: WorkerEndpoint, uuid: string, sni: string): string {
    return `vless://${uuid}@${ep.cleanIp}:${ep.port}?encryption=none&security=tls&sni=${sni}&type=ws&host=${ep.domain}&path=%2F#LumiNet-Worker`;
  }
}
