export interface SslVpnAdapterState {
  gateway: string;
  virtualIp: string;
  active: boolean;
  rxBytes: number;
  txBytes: number;
}

export class SslVpnAdapterUI {
  private active = false;
  private rx = 0;
  private tx = 0;
  public readonly gateway: string;
  public readonly virtualIp: string;
  constructor(gateway: string, virtualIp: string) {
    this.gateway = gateway;
    this.virtualIp = virtualIp;
  }

  activate(): boolean {
    this.active = true;
    return true;
  }

  recordBytes(rx: number, tx: number): void {
    this.rx += rx;
    this.tx += tx;
  }

  getState(): SslVpnAdapterState {
    return {
      gateway: this.gateway,
      virtualIp: this.virtualIp,
      active: this.active,
      rxBytes: this.rx,
      txBytes: this.tx,
    };
  }
}
