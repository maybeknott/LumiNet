export const BondingMode = {
  RoundRobin: 'round_robin',
  LowestLatency: 'lowest_latency',
  WeightedLoss: 'weighted_loss',
} as const;
export type BondingMode = (typeof BondingMode)[keyof typeof BondingMode];
export const PathState = {
  Active: 'active',
  Standby: 'standby',
  Degraded: 'degraded',
  Down: 'down',
} as const;
export type PathState = (typeof PathState)[keyof typeof PathState];

export interface PathMetrics {
  pathId: number;
  localAddr: string;
  remoteAddr: string;
  rttMs: number;
  lossPercentage: number;
  txBytes: number;
  rxBytes: number;
  state: PathState;
  weight: number;
}

export class MultipathTunnelManager {
  private paths: Map<number, PathMetrics> = new Map();
  private rrCounter = 0;
  public tunnelId: string;
  public mode: BondingMode;
  constructor(tunnelId: string, mode: BondingMode) {
    this.tunnelId = tunnelId;
    this.mode = mode;
  }

  addPath(path: PathMetrics): void {
    this.paths.set(path.pathId, path);
  }

  removePath(pathId: number): boolean {
    return this.paths.delete(pathId);
  }

  activePaths(): number[] {
    return Array.from(this.paths.values())
      .filter((p) => p.state === PathState.Active || p.state === PathState.Degraded)
      .map((p) => p.pathId);
  }

  selectPathForEgress(): number | null {
    const active = this.activePaths();
    if (active.length === 0) return null;

    switch (this.mode) {
      case BondingMode.RoundRobin: {
        const chosen = active[this.rrCounter % active.length]!;
        this.rrCounter++;
        return chosen;
      }
      case BondingMode.LowestLatency: {
        let best = active[0]!;
        let minRtt = Infinity;
        for (const id of active) {
          const p = this.paths.get(id)!;
          if (p.rttMs < minRtt) {
            minRtt = p.rttMs;
            best = id;
          }
        }
        return best;
      }
      default:
        return active[0]!;
    }
  }

  encapsulate(pathId: number, payload: Uint8Array): Uint8Array | null {
    const p = this.paths.get(pathId);
    if (!p) return null;
    p.txBytes += payload.length;

    const frame = new Uint8Array(7 + payload.length);
    const view = new DataView(frame.buffer);
    view.setUint32(0, pathId, false);
    view.setUint16(4, payload.length, false);
    frame[6] = 0x01;
    frame.set(payload, 7);
    return frame;
  }

  decapsulate(frame: Uint8Array): { pathId: number; payload: Uint8Array } | null {
    if (frame.length < 7) return null;
    const view = new DataView(frame.buffer, frame.byteOffset, frame.byteLength);
    const pathId = view.getUint32(0, false);
    const len = view.getUint16(4, false);
    if (frame.length < 7 + len) return null;

    const p = this.paths.get(pathId);
    if (p) p.rxBytes += len;

    return {
      pathId,
      payload: frame.slice(7, 7 + len),
    };
  }
}
