export type PolicyVerdict = 'DIRECT' | 'PROXY' | 'REJECT';

export interface CidrRuleEntry {
  netAddr: number;
  mask: number;
  verdict: PolicyVerdict;
}

export class PolicyRulesetRouter {
  private exactDomains = new Map<string, PolicyVerdict>();
  private suffixDomains = new Map<string, PolicyVerdict>();
  private keywordRules: Array<[string, PolicyVerdict]> = [];
  private cidrRules: CidrRuleEntry[] = [];
  private cache = new Map<string, PolicyVerdict>();
  public defaultPolicy: PolicyVerdict;
  constructor(defaultPolicy: PolicyVerdict = 'DIRECT') {
    this.defaultPolicy = defaultPolicy;
  }

  addExactDomain(domain: string, verdict: PolicyVerdict): void {
    this.exactDomains.set(domain.trim().toLowerCase(), verdict);
  }

  addSuffixDomain(suffix: string, verdict: PolicyVerdict): void {
    const clean = suffix.trim().toLowerCase().replace(/^\./, '');
    this.suffixDomains.set(clean, verdict);
  }

  addKeyword(keyword: string, verdict: PolicyVerdict): void {
    this.keywordRules.push([keyword.trim().toLowerCase(), verdict]);
  }

  addCidr(ipStr: string, maskBits: number, verdict: PolicyVerdict): void {
    const ipLong = this.ipToLong(ipStr);
    if (ipLong === null) return;
    const mask = maskBits === 0 ? 0 : (~0 << (32 - maskBits)) >>> 0;
    this.cidrRules.push({
      netAddr: (ipLong & mask) >>> 0,
      mask,
      verdict,
    });
  }

  resolveDomain(domain: string): PolicyVerdict {
    const clean = domain.trim().toLowerCase();
    const cached = this.cache.get(clean);
    if (cached) return cached;

    // 1. Exact match
    const exact = this.exactDomains.get(clean);
    if (exact) {
      this.cache.set(clean, exact);
      return exact;
    }

    // 2. Suffix match
    for (const [suffix, v] of this.suffixDomains.entries()) {
      if (clean === suffix || clean.endsWith(`.${suffix}`)) {
        this.cache.set(clean, v);
        return v;
      }
    }

    // 3. Keyword match
    for (const [kw, v] of this.keywordRules) {
      if (clean.includes(kw)) {
        this.cache.set(clean, v);
        return v;
      }
    }

    this.cache.set(clean, this.defaultPolicy);
    return this.defaultPolicy;
  }

  resolveIp(ipStr: string): PolicyVerdict {
    const ipLong = this.ipToLong(ipStr);
    if (ipLong === null) return this.defaultPolicy;
    for (const c of this.cidrRules) {
      if ((ipLong & c.mask) >>> 0 === c.netAddr) {
        return c.verdict;
      }
    }
    return this.defaultPolicy;
  }

  clearCache(): void {
    this.cache.clear();
  }

  private ipToLong(ip: string): number | null {
    const parts = ip.split('.').map((p) => parseInt(p, 10));
    if (parts.length !== 4 || parts.some((p) => isNaN(p) || p < 0 || p > 255)) {
      return null;
    }
    return ((parts[0]! << 24) | (parts[1]! << 16) | (parts[2]! << 8) | parts[3]!) >>> 0;
  }
}
