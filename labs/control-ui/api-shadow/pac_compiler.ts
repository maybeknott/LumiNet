export class PacScriptCompiler {
  private directDomains = new Set<string>();
  private proxyDomains = new Set<string>();
  public defaultProxy: string;
  constructor(defaultProxy: string) {
    this.defaultProxy = defaultProxy;
  }

  addDirectDomain(domain: string): void {
    const clean = domain.trim().replace(/^\./, '').toLowerCase();
    if (clean) this.directDomains.add(clean);
  }

  addProxyDomain(domain: string): void {
    const clean = domain.trim().replace(/^\./, '').toLowerCase();
    if (clean) this.proxyDomains.add(clean);
  }

  evaluateDomain(domain: string): string {
    const clean = domain.trim().replace(/^\./, '').toLowerCase();
    if (this.directDomains.has(clean)) return 'DIRECT';
    if (this.proxyDomains.has(clean)) return `PROXY ${this.defaultProxy}`;

    const parts = clean.split('.');
    for (let i = 1; i < parts.length; i++) {
      const sub = parts.slice(i).join('.');
      if (this.directDomains.has(sub)) return 'DIRECT';
      if (this.proxyDomains.has(sub)) return `PROXY ${this.defaultProxy}`;
    }
    return `PROXY ${this.defaultProxy}`;
  }

  compilePacScript(): string {
    return `// Control UI PAC Engine\nfunction FindProxyForURL(url, host) {\n  return 'PROXY ${this.defaultProxy}';\n}\n`;
  }
}
