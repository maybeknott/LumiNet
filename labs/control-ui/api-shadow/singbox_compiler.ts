export interface SingboxRule {
  type: string;
  value: string;
  outbound: string;
}

export class SingboxCompiler {
  public rules: SingboxRule[] = [];

  addRule(type: string, value: string, outbound: string): void {
    this.rules.push({ type, value, outbound });
  }

  matchDomain(domain: string): string | null {
    const lower = domain.trim().replace(/^\./, '').toLowerCase();
    for (const r of this.rules) {
      if (r.type === 'domain_suffix') {
        if (lower === r.value || lower.endsWith(`.${r.value}`)) return r.outbound;
      } else if (r.type === 'domain') {
        if (lower === r.value) return r.outbound;
      } else if (r.type === 'geosite' && r.value === 'cn') {
        if (lower.endsWith('.cn') || lower.includes('baidu')) return r.outbound;
      }
    }
    return null;
  }

  exportJson(): string {
    return JSON.stringify({
      version: 1,
      rules: this.rules.map(r => ({ [r.type]: [r.value], outbound: r.outbound })),
    }, null, 2);
  }
}
