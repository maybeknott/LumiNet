/**
 * Backend Proxy Node Reachability and WebSocket Diagnostic Client API
 *
 */

export interface BackendProbeRequest {
  targetUrl: string;
  path?: string;
  timeoutMs?: number;
}

export interface BackendProbeResult {
  ok: boolean;
  backendMode: boolean;
  backendUrl: string;
  targetTried: string;
  upstreamStatus?: number;
  gotWebSocket: boolean;
  elapsedMs: number;
  serverHeader?: string;
  steps: string[];
  fixHint?: string;
}

export interface SessionTrafficMetrics {
  userId: string;
  upBytes: number;
  downBytes: number;
  totalBytes: number;
}

export class BackendDiagnosticsService {
  private static baseUrl = '/api/v1';

  /**
   * Probes an upstream proxy endpoint for RFC 6455 WebSocket Upgrade compatibility.
   */
  static async probeBackend(req: BackendProbeRequest): Promise<BackendProbeResult> {
    const res = await fetch(`${this.baseUrl}/probe`, {
      method: 'POST',
      headers: {
        'Content-Type': 'application/json',
      },
      body: JSON.stringify({
        target_url: req.targetUrl,
        path: req.path,
        timeout: req.timeoutMs ? req.timeoutMs * 1000000 : undefined, // Convert ms to ns if passed to Go
      }),
    });

    if (!res.ok) {
      const errorText = await res.text();
      throw new Error(`Probe failed (${res.status}): ${errorText}`);
    }

    const data = await res.json();
    return {
      ok: data.ok,
      backendMode: data.backend_mode,
      backendUrl: data.backend_url,
      targetTried: data.target_tried,
      upstreamStatus: data.upstream_status,
      gotWebSocket: data.got_websocket,
      elapsedMs: data.elapsed_ms,
      serverHeader: data.server_header,
      steps: data.steps || [],
      fixHint: data.fix_hint,
    };
  }

  /**
   * Retrieves active duplex session traffic metrics.
   */
  static async getTrafficMetrics(userId: string): Promise<SessionTrafficMetrics> {
    const res = await fetch(`${this.baseUrl}/metrics/traffic?user_id=${encodeURIComponent(userId)}`);
    if (!res.ok) {
      throw new Error(`Failed to retrieve traffic metrics: ${res.statusText}`);
    }
    const data = await res.json();
    return {
      userId: data.user_id,
      upBytes: data.up_bytes,
      downBytes: data.down_bytes,
      totalBytes: (data.up_bytes || 0) + (data.down_bytes || 0),
    };
  }
}
