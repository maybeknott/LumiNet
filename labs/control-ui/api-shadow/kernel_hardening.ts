export interface SysctlRule {
  key: string;
  expected: string;
  critical: boolean;
}

export class KernelHardeningAuditor {
  private readonly rules: SysctlRule[] = [
    { key: 'net.ipv4.ip_forward', expected: '1', critical: true },
    { key: 'net.ipv4.conf.all.rp_filter', expected: '1', critical: true },
    { key: 'net.ipv4.conf.default.rp_filter', expected: '1', critical: true },
    { key: 'net.ipv4.conf.all.accept_source_route', expected: '0', critical: true },
    { key: 'net.ipv4.tcp_syncookies', expected: '1', critical: true }
  ];

  public audit(current: Record<string, string>): number {
    let compliant = 0;
    for (const r of this.rules) {
      if (current[r.key] === r.expected) {
        compliant++;
      }
    }
    return (compliant / this.rules.length) * 100;
  }
}
