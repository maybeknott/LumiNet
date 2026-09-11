export interface GatewayHealthMetric {
  endpoint: string;
  successRate: number;
  rttMs: number;
  activeConnections: number;
  isHealthy: boolean;
}

export class EdgeGatewayHealthMeter {
  private metrics = new Map<string, GatewayHealthMetric>();
  private maxRttThresholdMs: number;
  constructor(maxRttThresholdMs: number = 500) {
    this.maxRttThresholdMs = maxRttThresholdMs;
  }

  recordProbe(endpoint: string, rttMs: number, success: boolean, activeConns: number): void {
    const successRate = success ? 1.0 : 0.0;
    const isHealthy = success && rttMs <= this.maxRttThresholdMs;
    this.metrics.set(endpoint, {
      endpoint,
      successRate,
      rttMs,
      activeConnections: activeConns,
      isHealthy,
    });
  }

  getMetric(endpoint: string): GatewayHealthMetric | undefined {
    return this.metrics.get(endpoint);
  }

  healthyGateways(): string[] {
    return Array.from(this.metrics.values())
      .filter((m) => m.isHealthy)
      .map((m) => m.endpoint);
  }

  selectBestGateway(): string | undefined {
    const healthy = Array.from(this.metrics.values()).filter((m) => m.isHealthy);
    if (healthy.length === 0) return undefined;
    healthy.sort((a, b) => a.rttMs + a.activeConnections * 5 - (b.rttMs + b.activeConnections * 5));
    return healthy[0]!.endpoint;
  }
}
