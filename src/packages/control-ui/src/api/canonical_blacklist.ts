export const BlacklistVerdict = {
  Direct: 'direct',
  Blocked: 'blocked',
  Whitelisted: 'whitelisted',
} as const;
export type BlacklistVerdict = (typeof BlacklistVerdict)[keyof typeof BlacklistVerdict];

export class CanonicalBlacklistEngine {
  private exactBlocked = new Set<string>();
  private domainSuffixes = new Set<string>();
  private whitelistExact = new Set<string>();
  private whitelistSuffixes = new Set<string>();
  private keywords: string[] = [];

  parseRawRule(line: string): void {
    const trimmed = line.trim();
    if (!trimmed || trimmed.startsWith('!') || trimmed.startsWith('[')) return;

    if (trimmed.startsWith('@@')) {
      const rule = trimmed.slice(2);
      if (rule.startsWith('||')) {
        this.whitelistSuffixes.add(rule.slice(2).replace(/^\./, '').toLowerCase());
      } else {
        const clean = rule
          .replace(/^\|/, '')
          .replace(/^https?:\/\//, '')
          .replace(/^\./, '')
          .toLowerCase();
        this.whitelistExact.add(clean);
      }
      return;
    }

    if (trimmed.startsWith('||')) {
      this.domainSuffixes.add(trimmed.slice(2).replace(/^\./, '').toLowerCase());
      return;
    }

    if (trimmed.startsWith('|')) {
      const clean = trimmed
        .slice(1)
        .replace(/^https?:\/\//, '')
        .replace(/^\./, '')
        .toLowerCase();
      this.exactBlocked.add(clean);
      return;
    }

    if (!trimmed.startsWith('/')) {
      this.keywords.push(trimmed.toLowerCase());
    }
  }

  evaluateTarget(host: string): { verdict: BlacklistVerdict; rule: string } {
    const clean = host.trim().replace(/\.$/, '').toLowerCase();

    // 1. Whitelist
    if (this.whitelistExact.has(clean))
      return { verdict: BlacklistVerdict.Whitelisted, rule: clean };
    for (const suf of this.whitelistSuffixes) {
      if (clean === suf || clean.endsWith(`.${suf}`)) {
        return { verdict: BlacklistVerdict.Whitelisted, rule: suf };
      }
    }

    // 2. Exact blocked
    if (this.exactBlocked.has(clean)) return { verdict: BlacklistVerdict.Blocked, rule: clean };

    // 3. Suffix blocked
    for (const suf of this.domainSuffixes) {
      if (clean === suf || clean.endsWith(`.${suf}`)) {
        return { verdict: BlacklistVerdict.Blocked, rule: suf };
      }
    }

    // 4. Keywords
    for (const kw of this.keywords) {
      if (clean.includes(kw)) {
        return { verdict: BlacklistVerdict.Blocked, rule: kw };
      }
    }

    return { verdict: BlacklistVerdict.Direct, rule: '' };
  }
}
