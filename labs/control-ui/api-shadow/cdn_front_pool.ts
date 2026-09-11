export interface CdnCandidate {
  ip: string;
  sni: string;
  port: number;
  rttEmaMs: number;
  successCount: number;
  failureCount: number;
  quarantinedUntilMs: number;
}

export class CdnFrontPool {
  private candidates: CdnCandidate[] = [];
  private readonly quarantineDurationMs: number;
  private readonly maxCapacity: number;
  constructor(quarantineDurationMs: number = 60000, maxCapacity: number = 100) {
    this.quarantineDurationMs = quarantineDurationMs;
    this.maxCapacity = maxCapacity;
  }

  public addCandidate(ip: string, sni: string, port = 443): boolean {
    if (this.candidates.some((c) => c.ip === ip && c.sni === sni && c.port === port)) {
      return true;
    }
    if (this.candidates.length >= this.maxCapacity) {
      return false;
    }
    this.candidates.push({
      ip,
      sni,
      port,
      rttEmaMs: 0,
      successCount: 0,
      failureCount: 0,
      quarantinedUntilMs: 0,
    });
    return true;
  }

  public recordSuccess(ip: string, rttMs: number): void {
    const cand = this.candidates.find((c) => c.ip === ip);
    if (!cand) return;
    cand.successCount++;
    cand.rttEmaMs = cand.rttEmaMs === 0 ? rttMs : 0.8 * cand.rttEmaMs + 0.2 * rttMs;
  }

  public recordFailure(ip: string, nowMs = Date.now()): void {
    const cand = this.candidates.find((c) => c.ip === ip);
    if (!cand) return;
    cand.failureCount++;
    if (cand.failureCount % 3 === 0) {
      cand.quarantinedUntilMs = nowMs + this.quarantineDurationMs;
    }
  }

  public selectBest(nowMs = Date.now()): CdnCandidate | null {
    const healthy = this.candidates.filter((c) => nowMs >= c.quarantinedUntilMs);
    if (healthy.length === 0) return null;
    return healthy.reduce((best, cur) => {
      const scoreBest = best.rttEmaMs === 0 ? 50 : best.rttEmaMs;
      const scoreCur = cur.rttEmaMs === 0 ? 50 : cur.rttEmaMs;
      return scoreCur < scoreBest ? cur : best;
    });
  }

  public getCandidates(): readonly CdnCandidate[] {
    return this.candidates;
  }
}
