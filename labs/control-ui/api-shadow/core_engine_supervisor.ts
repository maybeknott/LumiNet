// Control UI TypeScript: Core Engine Supervisor API

export type EngineState = 'stopped' | 'starting' | 'running' | 'degraded' | 'crashed';

export interface EngineMetrics {
  pid: number;
  uptimeSeconds: number;
  memoryRssBytes: number;
  restartCount: number;
}

export interface SupervisorConfig {
  maxRestarts: number;
  memoryLimitBytes: number;
}

export class CoreEngineSupervisor {
  public config: SupervisorConfig;
  public state: EngineState = 'stopped';
  public metrics: EngineMetrics = {
    pid: 0,
    uptimeSeconds: 0,
    memoryRssBytes: 0,
    restartCount: 0,
  };

  constructor(config?: Partial<SupervisorConfig>) {
    this.config = {
      maxRestarts: config?.maxRestarts ?? 5,
      memoryLimitBytes: config?.memoryLimitBytes ?? 256 * 1024 * 1024,
    };
  }

  public start(pid: number): boolean {
    if (this.state === 'running') return false;
    this.state = 'running';
    this.metrics.pid = pid;
    this.metrics.uptimeSeconds = 0;
    return true;
  }

  public stop(): boolean {
    this.state = 'stopped';
    this.metrics.pid = 0;
    return true;
  }

  public handleProcessExit(exitCode: number): EngineState {
    if (exitCode === 0) {
      this.state = 'stopped';
      this.metrics.pid = 0;
    } else {
      this.metrics.restartCount++;
      if (this.metrics.restartCount > this.config.maxRestarts) {
        this.state = 'crashed';
      } else {
        this.state = 'degraded';
      }
    }
    return this.state;
  }

  public recordHeartbeat(elapsedSeconds: number, currentRssBytes: number): boolean {
    if (this.state !== 'running' && this.state !== 'degraded') return false;

    this.metrics.uptimeSeconds += elapsedSeconds;
    this.metrics.memoryRssBytes = currentRssBytes;

    if (currentRssBytes > this.config.memoryLimitBytes) {
      this.state = 'degraded';
      return false;
    }
    return true;
  }
}
