export interface UiLeakRecord {
  type: string;
  dstIp: string;
  iface: string;
}

export class LeakGuardSupervisor {
  public killswitchActive: boolean = true;
  private leaks: UiLeakRecord[] = [];
  public tunnelIface: string;
  public allowedDns: string[];
  public blockIpv6: boolean;
  constructor(tunnelIface: string, allowedDns: string[], blockIpv6: boolean = true) {
    this.tunnelIface = tunnelIface;
    this.allowedDns = allowedDns;
    this.blockIpv6 = blockIpv6;
  }

  validateOutbound(dstIp: string, dstPort: number, iface: string): boolean {
    if (!this.killswitchActive) return true;

    if (iface !== this.tunnelIface) {
      if ([53, 853, 5353].includes(dstPort)) {
        if (!this.allowedDns.includes(dstIp)) {
          this.leaks.push({ type: 'DNS_LEAK', dstIp, iface });
          return false;
        }
      }

      if (this.blockIpv6 && dstIp.includes(':')) {
        this.leaks.push({ type: 'IPV6_LEAK', dstIp, iface });
        return false;
      }
    }

    return true;
  }

  totalLeaks(): number {
    return this.leaks.length;
  }
}
