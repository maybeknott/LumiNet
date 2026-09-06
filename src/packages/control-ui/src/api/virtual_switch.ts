export interface SwitchPacketFrame {
  sourceHex: string; // 5 bytes (10 hex chars)
  destinationHex: string; // 5 bytes
  etherType: number;
  payload: Uint8Array;
}

export class VirtualEthernetSwitch {
  private readonly fdb = new Map<string, { endpoint: string; lastSeenMs: number }>();
  private readonly agingDurationMs: number;
  constructor(agingDurationMs: number = 60000) {
    this.agingDurationMs = agingDurationMs;
  }

  public learn(nodeIdHex: string, endpoint: string, nowMs = Date.now()): void {
    this.fdb.set(nodeIdHex, { endpoint, lastSeenMs: nowMs });
  }

  public lookup(nodeIdHex: string, nowMs = Date.now()): string | null {
    const entry = this.fdb.get(nodeIdHex);
    if (!entry) return null;
    if (nowMs - entry.lastSeenMs > this.agingDurationMs) {
      this.fdb.delete(nodeIdHex);
      return null;
    }
    return entry.endpoint;
  }
}
