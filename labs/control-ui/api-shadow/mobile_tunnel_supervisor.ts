export type MobileTunnelStatus =
  'DISCONNECTED' | 'CONNECTING' | 'CONNECTED' | 'RECONNECTING' | 'STOPPED';

export type SplitTunnelPolicy = 'ALLOW_ALL' | 'EXCLUDE_PACKAGES' | 'INCLUDE_PACKAGES';

export interface MobileSupervisorSettings {
  splitMode: SplitTunnelPolicy;
  packages: string[];
  primaryDns: string;
  fallbackDns: string;
  autoReconnect: boolean;
}

export class MobileTunnelSupervisor {
  state: MobileTunnelStatus = 'DISCONNECTED';
  private reconnectCount = 0;
  public settings: MobileSupervisorSettings;
  constructor(
    settings: MobileSupervisorSettings = {
      splitMode: 'ALLOW_ALL',
      packages: [],
      primaryDns: '1.1.1.1',
      fallbackDns: '8.8.8.8',
      autoReconnect: true,
    },
  ) {
    this.settings = settings;
  }

  startTunnel(): void {
    this.state = 'CONNECTING';
    this.state = 'CONNECTED';
    this.reconnectCount = 0;
  }

  stopTunnel(): void {
    this.state = 'STOPPED';
  }

  handleNetworkDrop(): void {
    if (this.settings.autoReconnect && this.state === 'CONNECTED') {
      this.state = 'RECONNECTING';
      this.reconnectCount++;
    } else {
      this.state = 'DISCONNECTED';
    }
  }

  isAppRouted(packageName: string): boolean {
    switch (this.settings.splitMode) {
      case 'ALLOW_ALL':
        return true;
      case 'EXCLUDE_PACKAGES':
        return !this.settings.packages.includes(packageName);
      case 'INCLUDE_PACKAGES':
        return this.settings.packages.includes(packageName);
    }
  }

  getEffectiveDns(useFallback: boolean): string {
    return useFallback ? this.settings.fallbackDns : this.settings.primaryDns;
  }

  getReconnectAttempts(): number {
    return this.reconnectCount;
  }
}
