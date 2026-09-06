export interface ProbeEntry {
  time: number;
  success: boolean;
  latencyMs: number;
}

export class UptimeIncidentTrackerUI {
  private history: ProbeEntry[] = [];
  private total = 0;
  private failed = 0;
  public readonly maxHistory;
  constructor(maxHistory = 100) {
    this.maxHistory = maxHistory;
  }

  record(success: boolean, latencyMs: number): void {
    this.total++;
    if (!success) this.failed++;

    this.history.push({ time: Date.now(), success, latencyMs });
    if (this.history.length > this.maxHistory) {
      this.history.shift();
    }
  }

  getAvailability(): number {
    if (this.total === 0) return 100.0;
    return ((this.total - this.failed) / this.total) * 100.0;
  }

  getHistory(): readonly ProbeEntry[] {
    return this.history;
  }
}
