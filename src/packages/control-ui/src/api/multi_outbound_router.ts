export type OutboundPolicyKind = 'DIRECT' | 'PROXY' | 'REJECT';

export interface OutboundPolicyDecision {
  type: OutboundPolicyKind;
  tag?: string;
}

export interface OutboundRouteRule {
  pattern: string;
  isSuffix: boolean;
  policy: OutboundPolicyDecision;
}

export class MultiOutboundRouter {
  private rules: OutboundRouteRule[] = [];
  private outboundWeights = new Map<string, number>();
  private rrCounter = 0;
  public defaultPolicy: OutboundPolicyDecision;
  constructor(defaultPolicy: OutboundPolicyDecision = { type: 'DIRECT' }) {
    this.defaultPolicy = defaultPolicy;
  }

  addRule(pattern: string, isSuffix: boolean, policy: OutboundPolicyDecision): void {
    this.rules.push({
      pattern: pattern.trim().toLowerCase(),
      isSuffix: Boolean(isSuffix),
      policy,
    });
  }

  registerOutbound(tag: string, weight: number): void {
    this.outboundWeights.set(tag, Math.max(1, weight));
  }

  matchTarget(host: string): OutboundPolicyDecision {
    const clean = host.trim().toLowerCase();
    for (const r of this.rules) {
      if (r.isSuffix) {
        if (clean === r.pattern || clean.endsWith(`.${r.pattern}`)) {
          return r.policy;
        }
      } else if (clean === r.pattern) {
        return r.policy;
      }
    }
    return this.defaultPolicy;
  }

  selectBalancedOutbound(outbounds: string[]): string | undefined {
    if (outbounds.length === 0) return undefined;
    const chosen = outbounds[this.rrCounter % outbounds.length];
    this.rrCounter++;
    return chosen;
  }
}
