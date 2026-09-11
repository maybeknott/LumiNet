export const PacRuleAction = {
  Direct: 'DIRECT',
  Proxy: 'PROXY',
} as const;
export type PacRuleAction = (typeof PacRuleAction)[keyof typeof PacRuleAction];

export interface PacRuleEntry {
  pattern: string;
  isExact: boolean;
  isSuffix: boolean;
  action: PacRuleAction;
  proxyEndpoint: string;
}

export class PacRuleGenerator {
  private rules: PacRuleEntry[] = [];
  public defaultAction: PacRuleAction;
  public defaultProxy: string;
  constructor(defaultAction: PacRuleAction = PacRuleAction.Direct, defaultProxy: string = '') {
    this.defaultAction = defaultAction;
    this.defaultProxy = defaultProxy;
  }

  addRule(pattern: string, action: PacRuleAction, proxyEndpoint: string): void {
    const trimmed = pattern.trim().toLowerCase();
    let isExact = false;
    let isSuffix = false;
    let pat = trimmed;

    if (trimmed.startsWith('||')) {
      isSuffix = true;
      pat = trimmed.substring(2);
    } else if (trimmed.startsWith('|')) {
      isExact = true;
      pat = trimmed.substring(1);
    }

    this.rules.push({ pattern: pat, isExact, isSuffix, action, proxyEndpoint });
  }

  evaluateHost(host: string): { action: PacRuleAction; proxyEndpoint: string } {
    const hostLower = host.toLowerCase();
    for (const r of this.rules) {
      if (r.isExact) {
        if (hostLower === r.pattern) return { action: r.action, proxyEndpoint: r.proxyEndpoint };
      } else if (r.isSuffix) {
        if (hostLower === r.pattern || hostLower.endsWith('.' + r.pattern)) {
          return { action: r.action, proxyEndpoint: r.proxyEndpoint };
        }
      } else if (hostLower.includes(r.pattern)) {
        return { action: r.action, proxyEndpoint: r.proxyEndpoint };
      }
    }
    return { action: this.defaultAction, proxyEndpoint: this.defaultProxy };
  }

  generatePacScript(): string {
    const rulesJs = this.rules
      .filter((r) => r.action === PacRuleAction.Proxy)
      .map((r) => `  "${r.pattern}": "PROXY ${r.proxyEndpoint}",`);
    const defRet =
      this.defaultAction === PacRuleAction.Proxy ? `"PROXY ${this.defaultProxy}"` : '"DIRECT"';

    return `// LumiNet Generated PAC
    var rules = {
    ${rulesJs.join('\n')}
    };

    function FindProxyForURL(url, host) {
    for (var d in rules) {
        if (dnsDomainIs(host, d) || host === d) {
            return rules[d];
        }
    }
    return ${defRet};
    }
    `;
  }
}
