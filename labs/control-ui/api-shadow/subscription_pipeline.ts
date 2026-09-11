export interface IngestedProxyNode {
  protocol: string;
  endpoint: string;
  tag: string;
}

interface NodeBufferShim {
  Buffer?: {
    from(input: string, encoding: string): { toString(encoding: string): string };
  };
}

function nodeGlobalBuffer() {
  return (globalThis as NodeBufferShim).Buffer;
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

export interface SubscriptionDiffResult {
  added: IngestedProxyNode[];
  removed: IngestedProxyNode[];
  modified: Array<{ old: IngestedProxyNode; new: IngestedProxyNode }>;
  unchanged: IngestedProxyNode[];
  hasChanges: boolean;
  summary: string;
}

/**
 * Computes the semantic diff between existing and newly fetched subscription nodes.
 * Identity is keyed by protocol and endpoint; tag updates are treated as modifications.
 */
export function computeSubscriptionDiff(
  oldNodes: IngestedProxyNode[],
  newNodes: IngestedProxyNode[]
): SubscriptionDiffResult {
  const oldMap = new Map<string, IngestedProxyNode>();
  for (const n of oldNodes) {
    const key = `${n.protocol}://${n.endpoint}`;
    oldMap.set(key, n);
  }

  const newMap = new Map<string, IngestedProxyNode>();
  for (const n of newNodes) {
    const key = `${n.protocol}://${n.endpoint}`;
    newMap.set(key, n);
  }

  const added: IngestedProxyNode[] = [];
  const modified: Array<{ old: IngestedProxyNode; new: IngestedProxyNode }> = [];
  const unchanged: IngestedProxyNode[] = [];

  for (const [key, newNode] of newMap.entries()) {
    const oldNode = oldMap.get(key);
    if (!oldNode) {
      added.push(newNode);
    } else if (oldNode.tag !== newNode.tag) {
      modified.push({ old: oldNode, new: newNode });
    } else {
      unchanged.push(newNode);
    }
  }

  const removed: IngestedProxyNode[] = [];
  for (const [key, oldNode] of oldMap.entries()) {
    if (!newMap.has(key)) {
      removed.push(oldNode);
    }
  }

  const hasChanges = added.length > 0 || removed.length > 0 || modified.length > 0;
  const parts: string[] = [];
  if (added.length > 0) parts.push(`+${added.length} added`);
  if (removed.length > 0) parts.push(`-${removed.length} removed`);
  if (modified.length > 0) parts.push(`~${modified.length} modified`);
  if (parts.length === 0) parts.push('No changes');

  return {
    added,
    removed,
    modified,
    unchanged,
    hasChanges,
    summary: parts.join(', '),
  };
}
