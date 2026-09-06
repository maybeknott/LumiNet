/**
 * Unified Proxy URI Codec and Normalizer
 */
export interface CanonicalProxyNode {
  protocol: string;
  uuidOrPassword: string;
  address: string;
  port: number;
  remark: string;
  params: Record<string, string>;
}

export class ProxyUriCodec {
  static parse(rawUri: string): CanonicalProxyNode | null {
    try {
      const trimmed = rawUri.trim();
      const idx = trimmed.indexOf('://');
      if (idx < 0) return null;

      const protocol = trimmed.slice(0, idx).toLowerCase();
      let rest = trimmed.slice(idx + 3);

      let remark = '';
      if (rest.includes('#')) {
        const parts = rest.split('#');
        rest = parts[0]!;
        remark = parts[1] ?? '';
      }

      let query = '';
      if (rest.includes('?')) {
        const parts = rest.split('?');
        rest = parts[0]!;
        query = parts[1] ?? '';
      }

      const atIdx = rest.lastIndexOf('@');
      if (atIdx < 0) return null;
      const cred = rest.slice(0, atIdx);
      const hostPort = rest.slice(atIdx + 1);

      const colonIdx = hostPort.lastIndexOf(':');
      const address = colonIdx >= 0 ? hostPort.slice(0, colonIdx) : hostPort;
      const port = colonIdx >= 0 ? parseInt(hostPort.slice(colonIdx + 1), 10) : 443;

      const params: Record<string, string> = {};
      if (query) {
        for (const kv of query.split('&')) {
          const [k, v] = kv.split('=');
          if (k) params[decodeURIComponent(k)] = v ? decodeURIComponent(v) : '';
        }
      }

      return { protocol, uuidOrPassword: cred, address, port, remark, params };
    } catch {
      return null;
    }
  }

  static serialize(node: CanonicalProxyNode): string {
    const keys = Object.keys(node.params).sort();
    const qParts = keys.map(
      (k) => `${encodeURIComponent(k)}=${encodeURIComponent(node.params[k]!)}`,
    );
    const qStr = qParts.length > 0 ? `?${qParts.join('&')}` : '';
    const rStr = node.remark ? `#${node.remark}` : '';
    return `${node.protocol}://${node.uuidOrPassword}@${node.address}:${node.port}${qStr}${rStr}`;
  }
}
