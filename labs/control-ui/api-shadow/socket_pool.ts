/**
 * Multi-Socket Connection Pool Supervisor
 */
export type SocketState = 'Active' | 'Standby' | 'Degraded' | 'Dead';

export interface ManagedSocket {
  id: string;
  endpoint: string;
  state: SocketState;
  failures: number;
  lastRttMs: number;
}

export class SocketPoolSupervisor {
  private sockets: Map<string, ManagedSocket> = new Map();
  public activeSocketId: string | null = null;

  registerSocket(id: string, endpoint: string): void {
    const isFirst = this.sockets.size === 0;
    const state: SocketState = isFirst ? 'Active' : 'Standby';
    if (isFirst) this.activeSocketId = id;
    this.sockets.set(id, { id, endpoint, state, failures: 0, lastRttMs: 0 });
  }

  recordHeartbeat(id: string, rttMs: number, success: boolean): void {
    const sock = this.sockets.get(id);
    if (!sock) return;

    sock.lastRttMs = rttMs;
    if (success) {
      sock.failures = 0;
      if (sock.state === 'Degraded') sock.state = 'Standby';
    } else {
      sock.failures++;
      sock.state = sock.failures >= 3 ? 'Dead' : 'Degraded';
    }

    if (this.activeSocketId === id && !success) {
      this.electNewActive();
    }
  }

  private electNewActive(): void {
    let bestId: string | null = null;
    let bestRtt = Infinity;

    for (const [id, s] of this.sockets.entries()) {
      if (s.state === 'Standby' && s.lastRttMs < bestRtt) {
        bestRtt = s.lastRttMs;
        bestId = id;
      }
    }

    if (bestId) {
      if (this.activeSocketId && this.sockets.has(this.activeSocketId)) {
        this.sockets.get(this.activeSocketId)!.state = 'Standby';
      }
      this.sockets.get(bestId)!.state = 'Active';
      this.activeSocketId = bestId;
    }
  }

  getActiveSocket(): ManagedSocket | null {
    return this.activeSocketId ? this.sockets.get(this.activeSocketId) ?? null : null;
  }
}
