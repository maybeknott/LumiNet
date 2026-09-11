export const EngineState = {
  Stopped: 'Stopped',
  Starting: 'Starting',
  Running: 'Running',
  Degraded: 'Degraded',
  Stopping: 'Stopping',
  Error: 'Error',
} as const;
export type EngineState = (typeof EngineState)[keyof typeof EngineState];

export interface EngineMetrics {
  uptimeSecs: number;
  rxBytes: number;
  txBytes: number;
  activeTunnels: number;
  lastHeartbeat: number;
}

export interface EngineConfig {
  bindAddress: string;
  socks5Port: number;
  httpPort: number;
  dnsPort: number;
  mtu: number;
  enableIpv6: boolean;
}

export class MobileEngineProvider {
  private state: EngineState = EngineState.Stopped;
  private metrics: EngineMetrics = {
    uptimeSecs: 0,
    rxBytes: 0,
    txBytes: 0,
    activeTunnels: 0,
    lastHeartbeat: 0,
  };
  private startTimestamp: number = 0;
  public config: EngineConfig;
  constructor(config: EngineConfig) {
    this.config = config;
  }

  startEngine(timestamp: number): void {
    if (this.state === EngineState.Running) {
      throw new Error('Engine is already running');
    }
    if (this.config.socks5Port === 0 || this.config.httpPort === 0) {
      this.state = EngineState.Error;
      throw new Error('Invalid port configuration');
    }

    this.state = EngineState.Starting;
    this.startTimestamp = timestamp;
    this.metrics.lastHeartbeat = timestamp;
    this.metrics.activeTunnels = 1;
    this.state = EngineState.Running;
  }

  stopEngine(): void {
    if (this.state === EngineState.Stopped) {
      return;
    }
    this.state = EngineState.Stopping;
    this.metrics.activeTunnels = 0;
    this.state = EngineState.Stopped;
  }

  recordTraffic(rx: number, tx: number, timestamp: number): void {
    this.metrics.rxBytes += rx;
    this.metrics.txBytes += tx;
    this.metrics.lastHeartbeat = timestamp;
    if (this.startTimestamp > 0 && timestamp >= this.startTimestamp) {
      this.metrics.uptimeSecs = timestamp - this.startTimestamp;
    }
  }

  markDegraded(degraded: boolean): void {
    if (this.state === EngineState.Running && degraded) {
      this.state = EngineState.Degraded;
    } else if (this.state === EngineState.Degraded && !degraded) {
      this.state = EngineState.Running;
    }
  }

  getState(): EngineState {
    return this.state;
  }

  getMetrics(): EngineMetrics {
    return { ...this.metrics };
  }
}
