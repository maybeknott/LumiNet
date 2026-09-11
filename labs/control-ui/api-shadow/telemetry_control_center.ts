export interface TelemetrySummary {
  activeTunnels: number;
  totalRxBytes: number;
  totalTxBytes: number;
  overallHealthPct: number;
  anomaliesDetected: number;
}

export class TelemetryControlCenter {
  private rx = 0;
  private tx = 0;
  private tunnels = 0;
  private anomalies = 0;

  updateTraffic(rx: number, tx: number): void {
    this.rx += rx;
    this.tx += tx;
  }

  setTunnelCount(count: number): void {
    this.tunnels = count;
  }

  recordAnomaly(): void {
    this.anomalies++;
  }

  getSummary(): TelemetrySummary {
    const health = Math.max(0, 100 - this.anomalies * 5);
    return {
      activeTunnels: this.tunnels,
      totalRxBytes: this.rx,
      totalTxBytes: this.tx,
      overallHealthPct: health,
      anomaliesDetected: this.anomalies,
    };
  }
}
