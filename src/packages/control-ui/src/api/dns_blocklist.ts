export const BlockCategory = {
  Malware: 'malware',
  Advertising: 'advertising',
  Tracking: 'tracking',
  Cryptomining: 'cryptomining',
  Adult: 'adult',
  Telemetry: 'telemetry',
} as const;
export type BlockCategory = (typeof BlockCategory)[keyof typeof BlockCategory];

export class DnsBlocklistEngine {
  private exactRules: Map<string, BlockCategory> = new Map();
  private wildcardRules: Map<string, BlockCategory> = new Map();
  private whitelist: Set<string> = new Set();
  private blockedIps: Set<string> = new Set();

  addExactRule(domain: string, category: BlockCategory): void {
    const clean = domain.trim().replace(/\.$/, '').toLowerCase();
    if (clean) this.exactRules.set(clean, category);
  }

  addWildcardRule(suffix: string, category: BlockCategory): void {
    let clean = suffix.trim().replace(/\.$/, '').toLowerCase();
    if (clean.startsWith('*.')) clean = clean.slice(2);
    if (clean.startsWith('.')) clean = clean.slice(1);
    if (clean) this.wildcardRules.set(clean, category);
  }

  addWhitelist(domain: string): void {
    const clean = domain.trim().replace(/\.$/, '').toLowerCase();
    if (clean) this.whitelist.add(clean);
  }

  addBlockedIp(ip: string): void {
    this.blockedIps.add(ip.trim());
  }

  isDomainBlocked(domain: string): BlockCategory | null {
    const clean = domain.trim().replace(/\.$/, '').toLowerCase();

    // 1. Whitelist
    if (this.whitelist.has(clean)) return null;
    const parts = clean.split('.');
    for (let i = 1; i < parts.length; i++) {
      const parent = parts.slice(i).join('.');
      if (this.whitelist.has(parent)) return null;
    }

    // 2. Exact match
    const exact = this.exactRules.get(clean);
    if (exact) return exact;

    // 3. Wildcard suffix
    for (const [suffix, cat] of this.wildcardRules.entries()) {
      if (clean === suffix || clean.endsWith(`.${suffix}`)) {
        return cat;
      }
    }
    return null;
  }

  isIpBlocked(ip: string): boolean {
    return this.blockedIps.has(ip.trim());
  }
}
