/**
 * Smooth Weighted Round-Robin (SWRR) Router
 */
export interface EgressRoute {
  id: string;
  endpoint: string;
  weight: number;
  currentWeight: number;
  healthy: boolean;
}

export class WeightedEgressRouter {
  private routes: EgressRoute[] = [];

  addRoute(id: string, endpoint: string, weight: number): void {
    this.routes.push({ id, endpoint, weight, currentWeight: 0, healthy: true });
  }

  setHealth(id: string, healthy: boolean): void {
    const r = this.routes.find((rt) => rt.id === id);
    if (r) {
      r.healthy = healthy;
      if (!healthy) r.currentWeight = 0;
    }
  }

  nextRoute(): string | null {
    const totalHealthy = this.routes
      .filter((r) => r.healthy && r.weight > 0)
      .reduce((acc, r) => acc + r.weight, 0);

    if (totalHealthy <= 0) return null;

    let best: EgressRoute | null = null;
    let maxWeight = -Infinity;

    for (const r of this.routes) {
      if (!r.healthy || r.weight <= 0) continue;
      r.currentWeight += r.weight;
      if (r.currentWeight > maxWeight) {
        maxWeight = r.currentWeight;
        best = r;
      }
    }

    if (best) {
      best.currentWeight -= totalHealthy;
      return best.endpoint;
    }
    return null;
  }
}
