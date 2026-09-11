export class AutoProxyMatcher {
  private directRules: string[] = [];
  private proxyRules: string[] = [];

  parseLine(line: string): void {
    const trimmed = line.trim();
    if (!trimmed || trimmed.startsWith('!') || trimmed.startsWith('[')) return;

    if (trimmed.startsWith('@@')) {
      const clean = trimmed.replace(/^@@/, '').replace(/^\|\|/, '').replace(/^\|/, '').toLowerCase();
      this.directRules.push(clean);
    } else {
      const clean = trimmed.replace(/^\|\|/, '').replace(/^\|/, '').toLowerCase();
      this.proxyRules.push(clean);
    }
  }

  match(url: string): 'DIRECT' | 'PROXY' | null {
    const lower = url.toLowerCase();
    for (const r of this.directRules) {
      if (lower.includes(r)) return 'DIRECT';
    }
    for (const r of this.proxyRules) {
      if (lower.includes(r)) return 'PROXY';
    }
    return null;
  }
}
