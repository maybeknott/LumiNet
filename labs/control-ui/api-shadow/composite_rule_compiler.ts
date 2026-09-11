export type ControlRuleAction = 'DIRECT' | 'PROXY' | 'REJECT';

export interface ControlCompiledRule {
  type: 'DOMAIN' | 'DOMAIN-SUFFIX' | 'DOMAIN-KEYWORD' | 'IP-CIDR' | 'USER-AGENT';
  pattern: string;
  netAddr?: number;
  mask?: number;
  action: ControlRuleAction;
}

export class CompositeRuleCompiler {
  private rules: ControlCompiledRule[] = [];

  parseLine(line: string): boolean {
    const trimmed = line.trim();
    if (!trimmed || trimmed.startsWith('#') || trimmed.startsWith('//')) {
      return false;
    }
    const parts = trimmed.split(',').map((s) => s.trim());
    if (parts.length < 3) return false;

    const rType = parts[0]!.toUpperCase();
    const pattern = parts[1]!;
    const action = parts[2]!.toUpperCase() as ControlRuleAction;

    if (!['DIRECT', 'PROXY', 'REJECT'].includes(action)) return false;

    if (rType === 'DOMAIN' || rType === 'DOMAIN-SUFFIX' || rType === 'DOMAIN-KEYWORD') {
      this.rules.push({
        type: rType,
        pattern: pattern.toLowerCase(),
        action,
      });
      return true;
    } else if (rType === 'IP-CIDR') {
      const [ipStr, maskStr] = pattern.split('/') as [string, string | undefined];
      const maskBits = maskStr ? parseInt(maskStr, 10) : 32;
      const ipLong = this.ipToLong(ipStr!);
      if (ipLong === null) return false;
      const mask = maskBits === 0 ? 0 : (~0 << (32 - maskBits)) >>> 0;
      this.rules.push({
        type: 'IP-CIDR',
        pattern,
        netAddr: (ipLong & mask) >>> 0,
        mask,
        action,
      });
      return true;
    } else if (rType === 'USER-AGENT') {
      this.rules.push({
        type: 'USER-AGENT',
        pattern,
        action,
      });
      return true;
    }
    return false;
  }

  evaluateDomain(domain: string): ControlRuleAction | undefined {
    const clean = domain.trim().toLowerCase();
    for (const r of this.rules) {
      if (r.type === 'DOMAIN' && clean === r.pattern) return r.action;
      if (r.type === 'DOMAIN-SUFFIX' && (clean === r.pattern || clean.endsWith(`.${r.pattern}`))) {
        return r.action;
      }
      if (r.type === 'DOMAIN-KEYWORD' && clean.includes(r.pattern)) return r.action;
    }
    return undefined;
  }

  evaluateIp(ipStr: string): ControlRuleAction | undefined {
    const ipLong = this.ipToLong(ipStr);
    if (ipLong === null) return undefined;
    for (const r of this.rules) {
      if (r.type === 'IP-CIDR' && r.netAddr !== undefined && r.mask !== undefined) {
        if ((ipLong & r.mask) >>> 0 === r.netAddr) {
          return r.action;
        }
      }
    }
    return undefined;
  }

  ruleCount(): number {
    return this.rules.length;
  }

  private ipToLong(ip: string): number | null {
    const parts = ip.split('.').map((p) => parseInt(p, 10));
    if (parts.length !== 4 || parts.some((p) => isNaN(p) || p < 0 || p > 255)) {
      return null;
    }
    return ((parts[0]! << 24) | (parts[1]! << 16) | (parts[2]! << 8) | parts[3]!) >>> 0;
  }
}

/**
 * AutoProxy & GFWList ruleset parser and URL evaluator.
 * Ported and refactored from donor AutoProxyRulesetMatcher.kt.
 */
export class AutoProxyRulesetMatcher {
  private directRules: string[] = [];
  private proxyRules: string[] = [];

  parseLine(rawLine: string): boolean {
    const trimmed = rawLine.trim();
    if (!trimmed || trimmed.startsWith('!') || trimmed.startsWith('[')) {
      return false;
    }

    if (trimmed.startsWith('@@')) {
      const rule = trimmed
        .replace(/^@@/, '')
        .replace(/^\|\|/, '')
        .replace(/^\|/, '')
        .toLowerCase();
      if (rule) {
        this.directRules.push(rule);
        return true;
      }
    } else {
      const rule = trimmed
        .replace(/^\|\|/, '')
        .replace(/^\|/, '')
        .toLowerCase();
      if (rule) {
        this.proxyRules.push(rule);
        return true;
      }
    }
    return false;
  }

  match(url: string): ControlRuleAction | undefined {
    const lower = url.toLowerCase();
    for (const r of this.directRules) {
      if (lower.includes(r)) return 'DIRECT';
    }
    for (const r of this.proxyRules) {
      if (lower.includes(r)) return 'PROXY';
    }
    return undefined;
  }

  rulesCount(): { direct: number; proxy: number } {
    return {
      direct: this.directRules.length,
      proxy: this.proxyRules.length,
    };
  }
}

