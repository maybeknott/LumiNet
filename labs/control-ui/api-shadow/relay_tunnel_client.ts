export interface RelayClientOptions {
  relayHost: string;
  relayPort: number;
  authToken?: string;
  targetHost: string;
  targetPort: number;
}

export class HttpRelayTunnelClientUI {
  private opts: RelayClientOptions;
  constructor(opts: RelayClientOptions) {
    this.opts = opts;
  }

  buildConnectHeaders(): string {
    const auth = this.opts.authToken
      ? `Proxy-Authorization: Bearer ${this.opts.authToken}\r\n`
      : '';
    return (
      `CONNECT ${this.opts.targetHost}:${this.opts.targetPort} HTTP/1.1\r\n` +
      `Host: ${this.opts.targetHost}:${this.opts.targetPort}\r\n` +
      `Proxy-Connection: Keep-Alive\r\n` +
      auth +
      `\r\n`
    );
  }
}
