export type BackendEngine = 'kcp_raw_socket' | 'violated_tcp_quic' | 'fallback_standard';

export interface BackendHealth {
  rttMs: number;
  lossRate: number;
  consecutiveFailures: number;
  isAlive: boolean;
}

export class DualBackendController {
  public engines = new Map<BackendEngine, BackendHealth>();
  public activeEngine: BackendEngine = 'kcp_raw_socket';

  constructor() {
    this.engines.set('kcp_raw_socket', { rttMs: 100, lossRate: 0, consecutiveFailures: 0, isAlive: true });
    this.engines.set('violated_tcp_quic', { rttMs: 100, lossRate: 0, consecutiveFailures: 0, isAlive: true });
    this.engines.set('fallback_standard', { rttMs: 100, lossRate: 0, consecutiveFailures: 0, isAlive: true });
  }

  recordMetrics(engine: BackendEngine, rttMs: number, lossRate: number, success: boolean): void {
    const h = this.engines.get(engine);
    if (!h) return;
    h.rttMs = rttMs;
    h.lossRate = lossRate;
    if (success) {
      h.consecutiveFailures = 0;
      h.isAlive = true;
    } else {
      h.consecutiveFailures++;
      if (h.consecutiveFailures >= 3) {
        h.isAlive = false;
      }
    }
  }

  selectEngine(): BackendEngine {
    if (this.engines.get(this.activeEngine)?.isAlive) {
      return this.activeEngine;
    }
    for (const eng of ['kcp_raw_socket', 'violated_tcp_quic', 'fallback_standard'] as BackendEngine[]) {
      if (this.engines.get(eng)?.isAlive) {
        this.activeEngine = eng;
        return eng;
      }
    }
    return 'fallback_standard';
  }
}
