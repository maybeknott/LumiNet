/**
 * Node Speedtest & Benchmark Matrix API client.
 */

export type SpeedActionType = 'TcpPing' | 'RealPing' | 'UdpEcho' | 'Speedtest';

export interface SpeedMatrixOptions {
  concurrency: number;
  probeTimeoutMs: number;
  speedtestUrl: string;
  speedtestDurationSecs: number;
  maxDownloadBytes: number;
  realPingUrl: string;
}

export const DEFAULT_SPEED_OPTIONS: SpeedMatrixOptions = {
  concurrency: 5,
  probeTimeoutMs: 3000,
  speedtestUrl: 'https://speed.cloudflare.com/__down?bytes=25000000',
  speedtestDurationSecs: 5,
  maxDownloadBytes: 50 * 1024 * 1024,
  realPingUrl: 'http://cp.cloudflare.com/generate_204',
};

export interface SpeedCandidateResult {
  candidateId: string;
  action: SpeedActionType;
  success: boolean;
  latencyMs?: number;
  downloadBytes: number;
  durationMillis: number;
  speedMbps: number;
  error?: string;
}

/**
 * Triggers batch speed benchmarking across target candidates via daemon API.
 */
export async function runBatchSpeedtest(
  action: SpeedActionType,
  targets: string[],
  customOptions?: Partial<SpeedMatrixOptions>
): Promise<SpeedCandidateResult[]> {
  const options = { ...DEFAULT_SPEED_OPTIONS, ...customOptions };

  const res = await fetch('/api/v1/speedtest/batch', {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({ action, targets, options }),
  });

  if (!res.ok) {
    throw new Error(`Speedtest failed with status ${res.status}: ${await res.text()}`);
  }

  return await res.json();
}

/**
 * Sends a cancellation request to interrupt any ongoing speed benchmarks.
 */
export async function cancelActiveSpeedtest(): Promise<void> {
  const res = await fetch('/api/v1/speedtest/cancel', {
    method: 'POST',
  });
  if (!res.ok) {
    throw new Error(`Failed to cancel speedtest: ${res.statusText}`);
  }
}

/**
 * Formats bandwidth throughput in human-readable strings.
 */
export function formatThroughput(speedMbps: number): string {
  if (speedMbps <= 0) return '0.00 Mbps';
  if (speedMbps >= 1000) {
    return `${(speedMbps / 1000).toFixed(2)} Gbps`;
  }
  return `${speedMbps.toFixed(2)} Mbps`;
}

/**
 * Formats ping latency with color-coded classification.
 */
export function formatLatency(latencyMs?: number): { text: string; quality: 'fast' | 'medium' | 'slow' | 'unreachable' } {
  if (latencyMs === undefined || latencyMs === null || latencyMs <= 0) {
    return { text: 'Timeout', quality: 'unreachable' };
  }
  if (latencyMs < 100) {
    return { text: `${latencyMs} ms`, quality: 'fast' };
  }
  if (latencyMs < 300) {
    return { text: `${latencyMs} ms`, quality: 'medium' };
  }
  return { text: `${latencyMs} ms`, quality: 'slow' };
}

/**
 * Sorts benchmark results by performance (latency asc for pings, speed desc for speedtests).
 */
export function sortCandidatesByPerformance(
  results: SpeedCandidateResult[],
  action: SpeedActionType
): SpeedCandidateResult[] {
  return [...results].sort((a, b) => {
    if (a.success !== b.success) {
      return a.success ? -1 : 1;
    }
    if (action === 'Speedtest') {
      return b.speedMbps - a.speedMbps;
    }
    return (a.latencyMs || 99999) - (b.latencyMs || 99999);
  });
}
