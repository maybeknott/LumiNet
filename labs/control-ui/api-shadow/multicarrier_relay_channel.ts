export const CarrierType = {
  Telecom: 'telecom',
  Unicom: 'unicom',
  Mobile: 'mobile',
  Satellite: 'satellite',
  Overlay: 'overlay',
} as const;
export type CarrierType = (typeof CarrierType)[keyof typeof CarrierType];

export interface CarrierRoute {
  carrier: CarrierType;
  endpoint: string;
  latencyMs: number;
  packetLoss: number;
  weight: number;
  isActive: boolean;
  consecutiveFailures: number;
}

export class MulticarrierRelayChannel {
  private routes: CarrierRoute[] = [];

  addRoute(route: CarrierRoute): void {
    this.routes.push({ ...route });
  }

  selectBestCarrier(): CarrierRoute | null {
    const active = this.routes.filter((r) => r.isActive);
    if (active.length === 0) return null;
    active.sort((a, b) => this.score(b) - this.score(a));
    return active[0]!;
  }

  recordFeedback(carrier: CarrierType, rttMs: number, success: boolean): void {
    for (const r of this.routes) {
      if (r.carrier === carrier) {
        if (success) {
          r.consecutiveFailures = 0;
          r.latencyMs = Math.floor((r.latencyMs * 3 + rttMs) / 4);
          r.packetLoss *= 0.8;
          r.isActive = true;
        } else {
          r.consecutiveFailures++;
          r.packetLoss = r.packetLoss * 0.8 + 0.2;
          if (r.consecutiveFailures >= 3) {
            r.isActive = false;
          }
        }
      }
    }
  }

  failoverSequence(): CarrierRoute[] {
    const copy = [...this.routes];
    copy.sort((a, b) => this.score(b) - this.score(a));
    return copy;
  }

  private score(r: CarrierRoute): number {
    const lat = Math.max(1, r.latencyMs);
    const loss = r.packetLoss;
    const fails = r.consecutiveFailures;
    return r.weight / (lat * (1.0 + loss * 5.0) * (1.0 + fails * 2.0));
  }
}
