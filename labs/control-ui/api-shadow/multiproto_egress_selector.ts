export interface UiEgressTarget {
  targetId: string;
  protocol: string;
  weight: number;
  latencyMs: number;
  lossPercent: number;
  isActive?: boolean;
}

export class MultiprotoEgressSelector {
  private targets: Map<string, UiEgressTarget> = new Map();

  addTarget(target: UiEgressTarget): void {
    this.targets.set(target.targetId, { ...target, isActive: target.isActive ?? true });
  }

  updateMetrics(targetId: string, latencyMs: number, lossPercent: number, isActive: boolean): boolean {
    const t = this.targets.get(targetId);
    if (!t) return false;
    t.latencyMs = latencyMs;
    t.lossPercent = lossPercent;
    t.isActive = isActive;
    return true;
  }

  selectBest(preferredProto?: string): UiEgressTarget | null {
    let best: UiEgressTarget | null = null;
    let bestScore = -1e9;

    for (const t of this.targets.values()) {
      if (!t.isActive) continue;
      let score = t.weight * 10 - t.latencyMs - t.lossPercent * 20;
      if (preferredProto && t.protocol === preferredProto) {
        score += 50;
      }
      if (score > bestScore) {
        bestScore = score;
        best = t;
      }
    }

    return best;
  }
}
