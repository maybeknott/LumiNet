// Control UI TypeScript: Universal Mesh Evasion Pipeline (Batch 10 Synthesis C1)

export type PipelineTransportTier =
  | 'direct_mesh'
  | 'hole_punched_mesh'
  | 'dpi_evaded_mesh'
  | 'stealth_bridge_fallback';

export interface PipelineMetrics {
  packetsProcessed: number;
  modeSwitches: number;
  currentTier: PipelineTransportTier;
}

export class UniversalMeshEvasionPipeline {
  public peerId: string;
  public consecutiveErrors: number = 0;
  public readonly escalationThreshold: number = 3;
  public metrics: PipelineMetrics = {
    packetsProcessed: 0,
    modeSwitches: 0,
    currentTier: 'direct_mesh',
  };

  constructor(peerId: string) {
    this.peerId = peerId;
  }

  public processOutboundFrame(frame: Uint8Array): Uint8Array[] {
    this.metrics.packetsProcessed++;

    switch (this.metrics.currentTier) {
      case 'direct_mesh':
      case 'hole_punched_mesh':
        return [frame];

      case 'dpi_evaded_mesh': {
        if (frame.length > 8) {
          const mid = Math.floor(frame.length / 2);
          return [frame.slice(0, mid), frame.slice(mid)];
        }
        return [frame];
      }

      case 'stealth_bridge_fallback': {
        const prefix = new TextEncoder().encode('STH:');
        const wrapped = new Uint8Array(prefix.length + frame.length);
        wrapped.set(prefix, 0);
        wrapped.set(frame, prefix.length);
        return [wrapped];
      }
    }
  }

  public reportFailure(): PipelineTransportTier {
    this.consecutiveErrors++;
    if (this.consecutiveErrors >= this.escalationThreshold) {
      this.consecutiveErrors = 0;
      let nextTier: PipelineTransportTier = this.metrics.currentTier;

      if (this.metrics.currentTier === 'direct_mesh') {
        nextTier = 'hole_punched_mesh';
      } else if (this.metrics.currentTier === 'hole_punched_mesh') {
        nextTier = 'dpi_evaded_mesh';
      } else if (this.metrics.currentTier === 'dpi_evaded_mesh') {
        nextTier = 'stealth_bridge_fallback';
      }

      if (nextTier !== this.metrics.currentTier) {
        this.metrics.currentTier = nextTier;
        this.metrics.modeSwitches++;
      }
    }
    return this.metrics.currentTier;
  }

  public reportSuccess(): void {
    this.consecutiveErrors = 0;
  }
}
