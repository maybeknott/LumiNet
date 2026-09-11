// Control UI TypeScript: Relay Rotation Circuit Breaker API

export type CircuitState = 'closed' | 'open' | 'half_open';

export interface RelayNode {
  id: string;
  endpoint: string;
  consecutiveFailures: number;
  successfulProbes: number;
  state: CircuitState;
  lastStateChangeMs: number;
}

export interface CircuitBreakerConfig {
  failureThreshold: number;
  halfOpenProbesNeeded: number;
  cooldownMs: number;
}

export class RelayRotationCircuitBreaker {
  public config: CircuitBreakerConfig;
  public relays: RelayNode[] = [];
  public currentIndex: number = 0;

  constructor(config?: Partial<CircuitBreakerConfig>) {
    this.config = {
      failureThreshold: config?.failureThreshold ?? 3,
      halfOpenProbesNeeded: config?.halfOpenProbesNeeded ?? 2,
      cooldownMs: config?.cooldownMs ?? 30_000,
    };
  }

  public registerRelay(id: string, endpoint: string): void {
    this.relays.push({
      id,
      endpoint,
      consecutiveFailures: 0,
      successfulProbes: 0,
      state: 'closed',
      lastStateChangeMs: 0,
    });
  }

  public selectActiveRelay(nowMs: number): string | null {
    const total = this.relays.length;
    if (total === 0) return null;

    for (let i = 0; i < total; i++) {
      const idx = (this.currentIndex + i) % total;
      const relay = this.relays[idx]!;

      if (relay.state === 'open') {
        if (nowMs - relay.lastStateChangeMs >= this.config.cooldownMs) {
          relay.state = 'half_open';
          relay.successfulProbes = 0;
          relay.lastStateChangeMs = nowMs;
          this.currentIndex = idx;
          return relay.id;
        }
      } else {
        this.currentIndex = idx;
        return relay.id;
      }
    }
    return null;
  }

  public recordSuccess(id: string, nowMs: number): void {
    const relay = this.relays.find((r) => r.id === id);
    if (!relay) return;

    relay.consecutiveFailures = 0;
    if (relay.state === 'half_open') {
      relay.successfulProbes++;
      if (relay.successfulProbes >= this.config.halfOpenProbesNeeded) {
        relay.state = 'closed';
        relay.lastStateChangeMs = nowMs;
      }
    }
  }

  public recordFailure(id: string, nowMs: number): void {
    const relay = this.relays.find((r) => r.id === id);
    if (!relay) return;

    relay.consecutiveFailures++;
    if (relay.state === 'closed' && relay.consecutiveFailures >= this.config.failureThreshold) {
      relay.state = 'open';
      relay.lastStateChangeMs = nowMs;
      this.currentIndex = (this.currentIndex + 1) % this.relays.length;
    } else if (relay.state === 'half_open') {
      relay.state = 'open';
      relay.lastStateChangeMs = nowMs;
      this.currentIndex = (this.currentIndex + 1) % this.relays.length;
    }
  }
}
