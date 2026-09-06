export interface DohEndpoint {
  url: string;
  host: string;
  tier: number;
  isHealthy: boolean;
  consecutiveFails: number;
  avgLatencyMs: number;
}

export class DohFallbackHierarchy {
  public endpoints: DohEndpoint[] = [
    {
      url: 'https://1.1.1.1/dns-query',
      host: 'cloudflare-dns.com',
      tier: 1,
      isHealthy: true,
      consecutiveFails: 0,
      avgLatencyMs: 25,
    },
    {
      url: 'https://dns.google/dns-query',
      host: 'dns.google',
      tier: 1,
      isHealthy: true,
      consecutiveFails: 0,
      avgLatencyMs: 35,
    },
    {
      url: 'https://doh.opendns.com/dns-query',
      host: 'doh.opendns.com',
      tier: 2,
      isHealthy: true,
      consecutiveFails: 0,
      avgLatencyMs: 60,
    },
  ];

  recordFailure(url: string): void {
    const ep = this.endpoints.find((e) => e.url === url);
    if (!ep) return;
    ep.consecutiveFails++;
    if (ep.consecutiveFails >= 3) {
      ep.isHealthy = false;
    }
  }

  selectActive(): DohEndpoint | null {
    const healthy = this.endpoints.filter((e) => e.isHealthy);
    if (healthy.length === 0) return this.endpoints[0] ?? null;

    return (
      [...healthy].sort((a, b) => {
        if (a.tier !== b.tier) return a.tier - b.tier;
        return a.avgLatencyMs - b.avgLatencyMs;
      })[0] ?? null
    );
  }
}
