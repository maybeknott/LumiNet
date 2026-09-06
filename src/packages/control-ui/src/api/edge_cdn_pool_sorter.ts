export interface EdgeIpStatus {
  ipAddress: string;
  latencyMs: number;
  packetLossRatio: number;
  isAvailable: boolean;
}

export class EdgeCdnPoolSorter {
  private ipPool = new Map<string, EdgeIpStatus>();
  private maxLatencyThresholdMs: number;
  constructor(maxLatencyThresholdMs: number = 300) {
    this.maxLatencyThresholdMs = maxLatencyThresholdMs;
  }

  addIp(ip: string): void {
    this.ipPool.set(ip, {
      ipAddress: ip,
      latencyMs: Infinity,
      packetLossRatio: 1.0,
      isAvailable: false,
    });
  }

  updateProbeResult(ip: string, latencyMs: number, success: boolean): void {
    const entry = this.ipPool.get(ip);
    if (!entry) return;

    if (success) {
      entry.latencyMs = latencyMs;
      entry.packetLossRatio = 0.0;
      entry.isAvailable = latencyMs <= this.maxLatencyThresholdMs;
    } else {
      entry.packetLossRatio = 1.0;
      entry.isAvailable = false;
    }
  }

  getSortedFastest(): EdgeIpStatus[] {
    return Array.from(this.ipPool.values())
      .filter((e) => e.isAvailable)
      .sort((a, b) => a.latencyMs - b.latencyMs);
  }

  bestIp(): string | undefined {
    return this.getSortedFastest()[0]?.ipAddress;
  }
}
