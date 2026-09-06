// Control UI TypeScript: Split Tunnel Routing Rule Synchronizer API

export type SplitRoutingAction = 'route_through_vpn' | 'bypass_vpn' | 'drop_traffic';

export interface SplitRule {
  id: string;
  networkStr: string;
  prefixLen: number;
  action: SplitRoutingAction;
  priority: number;
}

export class SplitTunnelRuleSync {
  public defaultAction: SplitRoutingAction;
  public rules: SplitRule[] = [];
  public syncVersion: number = 0;

  constructor(defaultAction: SplitRoutingAction = 'bypass_vpn') {
    this.defaultAction = defaultAction;
  }

  public addRule(
    id: string,
    cidr: string,
    action: SplitRoutingAction,
    priority: number = 100,
  ): void {
    const parts = cidr.trim().split('/');
    const netStr = parts[0]!;
    const prefix = parts.length === 2 ? parseInt(parts[1]!, 10) : 32;

    this.rules.push({
      id,
      networkStr: netStr,
      prefixLen: prefix,
      action,
      priority,
    });

    this.rules.sort((a, b) => {
      if (b.priority !== a.priority) return b.priority - a.priority;
      return b.prefixLen - a.prefixLen;
    });

    this.syncVersion++;
  }

  public matchIp(ip: string): SplitRoutingAction {
    for (const rule of this.rules) {
      if (this.isIpInSubnet(ip, rule.networkStr, rule.prefixLen)) {
        return rule.action;
      }
    }
    return this.defaultAction;
  }

  public syncFromFeed(feed: string, action: SplitRoutingAction): number {
    let count = 0;
    for (const line of feed.split('\n')) {
      const trimmed = line.trim();
      if (!trimmed || trimmed.startsWith('#')) continue;
      this.addRule(`feed-${count + 1}`, trimmed, action, 100);
      count++;
    }
    return count;
  }

  private isIpInSubnet(ip: string, network: string, prefix: number): boolean {
    const ipNum = this.ipToNum(ip);
    const netNum = this.ipToNum(network);
    const mask = prefix === 0 ? 0 : (~0 << (32 - prefix)) >>> 0;
    return (ipNum & mask) === (netNum & mask);
  }

  private ipToNum(ip: string): number {
    return ip.split('.').reduce((acc, octet) => ((acc << 8) + parseInt(octet, 10)) >>> 0, 0);
  }
}
