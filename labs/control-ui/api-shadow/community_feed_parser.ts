// Control UI TypeScript: Community Subscription Feed Parser API

export interface CommunityNode {
  id: string;
  protocol: string;
  server: string;
  port: number;
  credentials: string;
  transport: string;
  sni: string | null;
  tag: string;
}

export class CommunityFeedParser {
  public nodes: CommunityNode[] = [];

  public decodeFeed(raw: string): string {
    const trimmed = raw.trim();
    if (trimmed.startsWith('vless://') || trimmed.startsWith('vmess://') ||
        trimmed.startsWith('trojan://') || trimmed.startsWith('ss://')) {
      return trimmed;
    }

    try {
      const clean = trimmed.replace(/\s+/g, '');
      return atob(clean);
    } catch {
      return '';
    }
  }

  public parseUri(uriStr: string): CommunityNode | null {
    try {
      const trimmed = uriStr.trim();
      const url = new URL(trimmed);
      const scheme = url.protocol.replace(':', '').toLowerCase();
      const server = url.hostname;
      const port = url.port ? parseInt(url.port, 10) : 443;
      const credentials = url.username || '';
      const transport = url.searchParams.get('type') || 'tcp';
      const sni = url.searchParams.get('sni');
      const tag = url.hash ? decodeURIComponent(url.hash.slice(1)) : `${scheme}-node`;

      if (scheme === 'vless' || scheme === 'vmess' || scheme === 'trojan' || scheme === 'ss') {
        return {
          id: `${scheme}-${server}:${port}`,
          protocol: scheme,
          server,
          port,
          credentials,
          transport,
          sni,
          tag,
        };
      }
      return null;
    } catch {
      return null;
    }
  }

  public parseFeedContent(content: string): number {
    const decoded = this.decodeFeed(content);
    let added = 0;
    for (const line of decoded.split('\n')) {
      const trimmed = line.trim();
      if (trimmed) {
        const node = this.parseUri(trimmed);
        if (node) {
          this.nodes.push(node);
          added++;
        }
      }
    }
    return added;
  }

  public deduplicate(): number {
    const seen = new Set<string>();
    const initial = this.nodes.length;
    const unique: CommunityNode[] = [];

    for (const node of this.nodes) {
      const key = `${node.protocol}:${node.server}:${node.port}`;
      if (!seen.has(key)) {
        seen.add(key);
        unique.push(node);
      }
    }

    this.nodes = unique;
    return initial - unique.length;
  }
}
