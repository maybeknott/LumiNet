/**
 * Multi-node Iran Censorship & Edge Reachability Prober API.
 *
 * Ported and unified from `filtere-main`.
 * Provides probe query synthesis targeting canonical Iranian edge nodes on Check-Host,
 * asynchronous polling result deserialization, and multi-node quorum censorship assessment.
 */

export const DEFAULT_IRAN_NODES: string[] = [
  'ir1.node.check-host.net',
  'ir2.node.check-host.net',
  'ir3.node.check-host.net',
  'ir5.node.check-host.net',
  'ir6.node.check-host.net',
  'ir7.node.check-host.net',
  'ir8.node.check-host.net',
];

export type ProbeMethod = 'http' | 'ping' | 'dns';

export type CensorshipVerdict = 'clean' | 'filtered' | 'high_loss' | 'degraded' | 'indeterminate';

export interface NodeProbeResult {
  node: string;
  responsive: boolean;
  rttMs?: number | undefined;
  error?: string | undefined;
  extraInfo?: string | undefined;
}

export interface CheckHostAssessment {
  target: string;
  method: ProbeMethod;
  verdict: CensorshipVerdict;
  totalNodes: number;
  responsiveNodes: number;
  blockedNodes: number;
  avgRttMs?: number | undefined;
  nodeResults: Record<string, NodeProbeResult>;
  isReady: boolean;
}

/**
 * Builds the URL to initiate a probe with Check-Host.
 */
export function buildCheckHostUrl(
  target: string,
  method: ProbeMethod,
  nodes: string[] = DEFAULT_IRAN_NODES,
): string {
  const selectedNodes = nodes.length > 0 ? nodes : DEFAULT_IRAN_NODES;
  const params = new URLSearchParams();
  params.set('host', target);
  for (const n of selectedNodes) {
    params.append('node', n.trim());
  }
  return `https://check-host.net/check-${method}?${params.toString()}`;
}

/**
 * Builds the result polling URL for a given request ID.
 */
export function buildResultUrl(requestId: string): string {
  return `https://check-host.net/check-result/${encodeURIComponent(requestId)}`;
}

/**
 * Extracts request ID from the initiation response.
 */
export function parseInitiateResponse(
  raw: string | { ok?: number; request_id?: string; error?: string },
): string {
  const data = typeof raw === 'string' ? JSON.parse(raw) : raw;
  if (data.error) {
    throw new Error(`Check-Host initiation error: ${data.error}`);
  }
  if (!data.request_id) {
    throw new Error('No request_id returned in Check-Host response');
  }
  return data.request_id;
}

/**
 * Evaluates reachability and censorship verdict given responsive counts and loss metrics.
 */
export function evaluateVerdict(
  responsive: number,
  total: number,
  avgLossPct: number,
): CensorshipVerdict {
  if (total === 0) {
    return 'indeterminate';
  }
  const ratio = responsive / total;
  if (responsive === 0 || ratio <= 0.35) {
    return 'filtered';
  }
  if (ratio >= 0.75) {
    if (avgLossPct > 40) return 'high_loss';
    if (avgLossPct > 15) return 'degraded';
    return 'clean';
  }
  return 'degraded';
}

/**
 * Parses Check-Host result payload and calculates quorum assessment.
 */
export function parseResultResponse(
  raw: string | Record<string, unknown>,
  target: string,
  method: ProbeMethod,
): CheckHostAssessment {
  const data = (typeof raw === 'string' ? JSON.parse(raw) : raw) as Record<string, unknown>;

  const nodeResults: Record<string, NodeProbeResult> = {};
  let responsiveCount = 0;
  let blockedCount = 0;
  let rttSum = 0;
  let rttCount = 0;
  let totalLossSum = 0;
  let anyPending = false;

  for (const [nodeName, val] of Object.entries(data)) {
    if (val === null || val === undefined) {
      anyPending = true;
      continue;
    }

    let responsive = false;
    let nodeRtt: number | undefined;
    let error: string | undefined;
    let extraInfo: string | undefined;

    if (method === 'ping' && Array.isArray(val)) {
      const samples: number[] = [];
      for (const outer of val) {
        if (Array.isArray(outer)) {
          for (const item of outer) {
            if (Array.isArray(item) && item.length >= 2) {
              const status = item[0];
              if (status === 'OK') {
                const sec = typeof item[1] === 'number' ? item[1] : 0;
                samples.push(sec * 1000);
              } else if (!error && typeof status === 'string') {
                error = status;
              }
            }
          }
        }
      }

      if (samples.length > 0) {
        responsive = true;
        const avg = samples.reduce((acc, v) => acc + v, 0) / samples.length;
        nodeRtt = avg;
        rttSum += avg;
        rttCount++;
        extraInfo = `samples: ${samples.length}`;
      } else {
        totalLossSum += 100;
      }
    } else if (method === 'http' && Array.isArray(val) && val.length > 0) {
      const attempt = val[0];
      if (Array.isArray(attempt) && attempt.length >= 3) {
        const okFlag = attempt[0] === 1;
        const rttSec = typeof attempt[1] === 'number' ? attempt[1] : 0;
        const phrase = typeof attempt[2] === 'string' ? attempt[2] : '';
        const statusCode = attempt[3] != null ? String(attempt[3]) : '';
        const ip = attempt[4] != null ? String(attempt[4]) : '';

        if (okFlag) {
          responsive = true;
          const ms = rttSec * 1000;
          nodeRtt = ms;
          rttSum += ms;
          rttCount++;
          extraInfo = `HTTP ${statusCode} (${phrase}) -> ${ip}`;
        } else {
          error = phrase || 'Connection timed out or reset';
          totalLossSum += 100;
        }
      }
    } else if (method === 'dns' && Array.isArray(val) && val.length > 0) {
      const dnsObj = val[0] as { A?: string[] };
      if (dnsObj && Array.isArray(dnsObj.A) && dnsObj.A.length > 0) {
        responsive = true;
        extraInfo = `A: ${dnsObj.A.join(', ')}`;
      } else {
        error = 'DNS resolution timed out or NXDOMAIN';
        totalLossSum += 100;
      }
    }

    if (responsive) {
      responsiveCount++;
    } else {
      blockedCount++;
    }

    nodeResults[nodeName] = {
      node: nodeName,
      responsive,
      rttMs: nodeRtt,
      error,
      extraInfo,
    };
  }

  const evaluated = responsiveCount + blockedCount;
  const avgLoss = evaluated > 0 ? totalLossSum / evaluated : 0;
  const avgRtt = rttCount > 0 ? rttSum / rttCount : undefined;
  const verdict = evaluateVerdict(responsiveCount, evaluated, avgLoss);

  return {
    target,
    method,
    verdict,
    totalNodes: evaluated,
    responsiveNodes: responsiveCount,
    blockedNodes: blockedCount,
    avgRttMs: avgRtt,
    nodeResults,
    isReady: !anyPending && evaluated > 0,
  };
}
