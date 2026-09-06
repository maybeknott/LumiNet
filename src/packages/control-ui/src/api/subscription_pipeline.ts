export interface IngestedProxyNode {
  protocol: string;
  endpoint: string;
  tag: string;
}

export function parseSubscriptionPayload(content: string): IngestedProxyNode[] {
  let decoded = content.trim();
  try {
    // Attempt base64 decode
    if (typeof atob === 'function') {
      decoded = atob(decoded);
    } else {
      const buf = nodeGlobalBuffer();
      if (buf) {
        decoded = buf.from(decoded, 'base64').toString('utf-8');
      }
    }
  } catch {
    // Fallback to plain string
  }

  const lines = decoded.split('\n');
  const nodes: IngestedProxyNode[] = [];
  const seen = new Set<string>();

  for (const rawLine of lines) {
    const line = rawLine.trim();
    if (!line || line.startsWith('#') || !line.includes('://')) continue;

    const [protocol, restWithTag] = line.split('://', 2);
    let endpoint = restWithTag;
    let tag = '';
    if (restWithTag?.includes('#')) {
      const parts = (restWithTag ?? '').split('#', 2);
      endpoint = parts[0];
      tag = parts[1]!;
    }

    if (!seen.has(line)) {
      seen.add(line);
      nodes.push({ protocol: protocol!, endpoint: endpoint!, tag });
    }
  }

  return nodes;
}
