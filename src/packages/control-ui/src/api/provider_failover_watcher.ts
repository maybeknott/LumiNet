export type ProviderStatusType = 'OPERATIONAL' | 'UNSTABLE' | 'FAILED';

export interface ProviderHealthState {
  providerName: string;
  consecutiveFailures: number;
  successfulHeartbeats: number;
  lastLatencyMs: number;
  status: ProviderStatusType;
}

export class ProviderFailoverWatcher {
  private providers = new Map<string, ProviderHealthState>();
  activeProvider?: string;
  private failoverThreshold: number;
  constructor(failoverThreshold: number = 3) {
    this.failoverThreshold = failoverThreshold;
  }

  registerProvider(name: string, isActive: boolean): void {
    this.providers.set(name, {
      providerName: name,
      consecutiveFailures: 0,
      successfulHeartbeats: 0,
      lastLatencyMs: 0,
      status: 'OPERATIONAL',
    });
    if (isActive) {
      this.activeProvider = name;
    }
  }

  recordHeartbeat(name: string, latencyMs: number, success: boolean): string | undefined {
    const p = this.providers.get(name);
    if (!p) return undefined;

    let needsFailover = false;
    if (success) {
      p.consecutiveFailures = 0;
      p.successfulHeartbeats++;
      p.lastLatencyMs = latencyMs;
      p.status = 'OPERATIONAL';
    } else {
      p.consecutiveFailures++;
      if (p.consecutiveFailures >= this.failoverThreshold) {
        p.status = 'FAILED';
        needsFailover = true;
      } else {
        p.status = 'UNSTABLE';
      }
    }

    if (needsFailover && this.activeProvider === name) {
      return this.failoverToNext();
    }
    return undefined;
  }

  failoverToNext(): string | undefined {
    for (const p of this.providers.values()) {
      if (p.status === 'OPERATIONAL' && p.providerName !== this.activeProvider) {
        this.activeProvider = p.providerName;
        return p.providerName;
      }
    }
    return undefined;
  }

  getHealth(name: string): ProviderHealthState | undefined {
    return this.providers.get(name);
  }
}
