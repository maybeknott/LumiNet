export interface SniRewriteRule {
  originalDomain: string;
  alteredSni: string;
  validSans: string[];
  skipCertVerify?: boolean;
}

export class SniHostnameRewriter {
  private rules: Map<string, SniRewriteRule> = new Map();
  private httpRedirects: Map<string, string> = new Map();
  public totalRewrites = 0;

  addSniRule(original: string, altered: string, validSans: string[], skipCertVerify = false): void {
    const key = original.trim().replace(/\.$/, '').toLowerCase();
    this.rules.set(key, {
      originalDomain: key,
      alteredSni: altered.trim().replace(/\.$/, '').toLowerCase(),
      validSans: validSans.map((s) => s.toLowerCase()),
      skipCertVerify
    });
  }

  addHttpRedirect(prefix: string, targetUrl: string): void {
    this.httpRedirects.set(prefix, targetUrl);
  }

  resolveSni(domain: string): { sni: string; rule?: SniRewriteRule } {
    const key = domain.trim().replace(/\.$/, '').toLowerCase();
    const rule = this.rules.get(key);
    if (rule) {
      this.totalRewrites++;
      return { sni: rule.alteredSni, rule };
    }
    return { sni: domain };
  }

  checkSanValidity(rule: SniRewriteRule, presentedSans: string[]): boolean {
    if (rule.skipCertVerify) return true;
    for (const valid of rule.validSans) {
      for (const pres of presentedSans) {
        const presLower = pres.toLowerCase();
        if (valid.startsWith('*.')) {
          if (presLower.endsWith(valid.slice(2))) return true;
        } else if (presLower === valid) {
          return true;
        }
      }
    }
    return false;
  }

  checkHttpRedirect(url: string): string | null {
    for (const [prefix, target] of this.httpRedirects.entries()) {
      if (url.startsWith(prefix)) {
        return `https://${target}`;
      }
    }
    return null;
  }
}
