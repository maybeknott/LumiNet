// Control UI TypeScript: Asynchronous Multi-Condition Rule Evaluator API

export type RuleKind =
  | 'domain'
  | 'domain_suffix'
  | 'domain_keyword'
  | 'ip_cidr'
  | 'port_range'
  | 'process_name'
  | 'match';

export interface EvaluatorRule {
  kind: RuleKind;
  value?: string;
  cidrNet?: string;
  cidrPrefix?: number;
  portStart?: number;
  portEnd?: number;
  targetOutbound: string;
  priority: number;
}

export interface TrafficTarget {
  domain?: string;
  ip?: string;
  port?: number;
  processName?: string;
}

export class AsyncRuleEvaluator {
  public defaultOutbound: string;
  public rules: EvaluatorRule[] = [];

  constructor(defaultOutbound: string = 'DIRECT') {
    this.defaultOutbound = defaultOutbound;
  }

  public addRule(rule: EvaluatorRule): void {
    this.rules.push(rule);
    this.rules.sort((a, b) => b.priority - a.priority);
  }

  public evaluate(target: TrafficTarget): string {
    for (const rule of this.rules) {
      if (this.matches(rule, target)) {
        return rule.targetOutbound;
      }
    }
    return this.defaultOutbound;
  }

  private matches(rule: EvaluatorRule, target: TrafficTarget): boolean {
    switch (rule.kind) {
      case 'domain':
        return !!target.domain && target.domain.toLowerCase() === (rule.value || '').toLowerCase();

      case 'domain_suffix': {
        if (!target.domain) return false;
        const d = target.domain.toLowerCase();
        const s = (rule.value || '').toLowerCase();
        return d === s || d.endsWith(`.${s}`);
      }

      case 'domain_keyword':
        return !!target.domain && target.domain.toLowerCase().includes((rule.value || '').toLowerCase());

      case 'ip_cidr': {
        if (!target.ip || !rule.cidrNet) return false;
        return this.isIpInSubnet(target.ip, rule.cidrNet, rule.cidrPrefix ?? 32);
      }

      case 'port_range': {
        if (target.port === undefined) return false;
        const start = rule.portStart ?? 0;
        const end = rule.portEnd ?? 65535;
        return target.port >= start && target.port <= end;
      }

      case 'process_name':
        return !!target.processName && target.processName.toLowerCase() === (rule.value || '').toLowerCase();

      case 'match':
        return true;

      default:
        return false;
    }
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
