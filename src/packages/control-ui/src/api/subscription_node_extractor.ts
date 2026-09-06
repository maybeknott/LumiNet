export type ControlProxyType = 'vmess' | 'shadowsocks' | 'trojan' | 'vless' | 'unknown';

export interface ExtractedProxyNode {
  nodeType: ControlProxyType;
  address: string;
  port: number;
  credential: string;
  remark: string;
}

export class SubscriptionNodeExtractor {
  decodeSubscription(base64Content: string): ExtractedProxyNode[] {
    const clean = base64Content.replace(/\r|\n/g, '').trim();
    let decoded = '';
    try {
      decoded = atob(clean);
    } catch {
      return [];
    }

    const lines = decoded
      .split('\n')
      .map((l) => l.trim())
      .filter((l) => l.length > 0);
    const nodes: ExtractedProxyNode[] = [];

    for (const line of lines) {
      if (line.startsWith('trojan://')) {
        const n = this.parseTrojan(line);
        if (n) nodes.push(n);
      } else if (line.startsWith('ss://')) {
        const n = this.parseShadowsocks(line);
        if (n) nodes.push(n);
      } else if (line.startsWith('vless://')) {
        const n = this.parseVless(line);
        if (n) nodes.push(n);
      } else if (line.startsWith('vmess://')) {
        const n = this.parseVmess(line);
        if (n) nodes.push(n);
      }
    }
    return nodes;
  }

  private parseTrojan(uriStr: string): ExtractedProxyNode | null {
    try {
      const url = new URL(uriStr);
      return {
        nodeType: 'trojan',
        address: url.hostname,
        port: url.port ? parseInt(url.port, 10) : 443,
        credential: url.username || '',
        remark: decodeURIComponent(url.hash.replace('#', '')),
      };
    } catch {
      return null;
    }
  }

  private parseVless(uriStr: string): ExtractedProxyNode | null {
    try {
      const url = new URL(uriStr);
      return {
        nodeType: 'vless',
        address: url.hostname,
        port: url.port ? parseInt(url.port, 10) : 443,
        credential: url.username || '',
        remark: decodeURIComponent(url.hash.replace('#', '')),
      };
    } catch {
      return null;
    }
  }

  private parseShadowsocks(uriStr: string): ExtractedProxyNode | null {
    try {
      const withoutScheme = uriStr.replace('ss://', '');
      const [mainPart, rawRemark] = withoutScheme.split('#');
      const remark = rawRemark ? decodeURIComponent(rawRemark) : '';

      if (mainPart?.includes('@')) {
        const [cred, hostPort] = mainPart.split('@') as [string, string];
        const [host, portStr] = hostPort.split(':') as [string, string];
        return {
          nodeType: 'shadowsocks',
          address: host,
          port: portStr ? parseInt(portStr, 10) : 8388,
          credential: cred,
          remark,
        };
      }
      return null;
    } catch {
      return null;
    }
  }

  private parseVmess(uriStr: string): ExtractedProxyNode | null {
    try {
      const b64 = uriStr.replace('vmess://', '').trim();
      const decodedJson = atob(b64);
      const data = JSON.parse(decodedJson);
      return {
        nodeType: 'vmess',
        address: data.add || 'unknown',
        port: data.port ? parseInt(data.port, 10) : 443,
        credential: data.id || '',
        remark: data.ps || '',
      };
    } catch {
      return null;
    }
  }
}
