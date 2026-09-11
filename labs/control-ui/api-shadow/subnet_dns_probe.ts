export interface DnsCandidateRecord {
  ip: string;
  latencyMs: number;
  isResponsive: boolean;
  isPoisoned: boolean;
}

export class SubnetDnsScanner {
  private readonly servers = new Map<string, DnsCandidateRecord>();
  private readonly expectedIp;
  constructor(expectedIp = '93.184.216.34') {
    this.expectedIp = expectedIp;
  }

  public recordProbe(
    ip: string,
    latencyMs: number,
    resolvedIp: string | null,
    hasError: boolean,
  ): void {
    if (hasError || resolvedIp === null) {
      this.servers.set(ip, {
        ip,
        latencyMs: 0,
        isResponsive: false,
        isPoisoned: false,
      });
      return;
    }
    const isPoisoned = resolvedIp !== this.expectedIp;
    this.servers.set(ip, { ip, latencyMs, isResponsive: true, isPoisoned });
  }

  public selectCleanFastest(): DnsCandidateRecord | null {
    const clean = Array.from(this.servers.values()).filter((s) => s.isResponsive && !s.isPoisoned);
    if (clean.length === 0) return null;
    return clean.reduce((best, cur) => (cur.latencyMs < best.latencyMs ? cur : best));
  }
}
