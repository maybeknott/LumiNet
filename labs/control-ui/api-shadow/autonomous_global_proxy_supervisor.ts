// Control UI TypeScript: Autonomous Global Proxy Supervisor (Batch 10 Synthesis C2)
// Unified control-plane supervisor orchestrating all 147 Wave 2 absorbed subsystems.

export interface SubsystemHealth {
  name: string;
  plane: string;
  isHealthy: boolean;
  activeConnections: number;
  lastHeartbeatMs: number;
  lastError: string | null;
}

export interface GlobalSystemReport {
  totalSubsystems: number;
  healthySubsystems: number;
  healthPercentage: number;
  totalActiveConnections: number;
  killswitchEngaged: boolean;
}

export class AutonomousGlobalProxySupervisor {
  public subsystems: Map<string, SubsystemHealth> = new Map();
  public killswitchEngaged: boolean = false;
  public autoRemediationEnabled: boolean;

  constructor(autoRemediationEnabled: boolean = true) {
    this.autoRemediationEnabled = autoRemediationEnabled;
  }

  public registerSubsystem(name: string, plane: string): void {
    this.subsystems.set(name, {
      name,
      plane,
      isHealthy: true,
      activeConnections: 0,
      lastHeartbeatMs: 0,
      lastError: null,
    });
  }

  public updateHealth(
    name: string,
    healthy: boolean,
    activeConnections: number,
    nowMs: number,
    error: string | null = null
  ): boolean {
    const sub = this.subsystems.get(name);
    if (!sub) return false;

    sub.isHealthy = healthy;
    sub.activeConnections = activeConnections;
    sub.lastHeartbeatMs = nowMs;
    sub.lastError = error;
    return true;
  }

  public setKillswitch(engaged: boolean): void {
    this.killswitchEngaged = engaged;
    if (engaged) {
      for (const sub of this.subsystems.values()) {
        sub.activeConnections = 0;
      }
    }
  }

  public generateReport(): GlobalSystemReport {
    const total = this.subsystems.size;
    let healthy = 0;
    let conns = 0;

    for (const sub of this.subsystems.values()) {
      if (sub.isHealthy) healthy++;
      conns += sub.activeConnections;
    }

    const pct = total === 0 ? 100 : (healthy / total) * 100;

    return {
      totalSubsystems: total,
      healthySubsystems: healthy,
      healthPercentage: pct,
      totalActiveConnections: conns,
      killswitchEngaged: this.killswitchEngaged,
    };
  }

  public identifyRemediationTargets(nowMs: number, staleTimeoutMs: number): string[] {
    if (!this.autoRemediationEnabled) return [];

    const targets: string[] = [];
    for (const sub of this.subsystems.values()) {
      if (!sub.isHealthy || (nowMs - sub.lastHeartbeatMs > staleTimeoutMs && sub.lastHeartbeatMs > 0)) {
        targets.push(sub.name);
      }
    }
    return targets;
  }
}
