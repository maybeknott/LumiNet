export const ProxyProtocolVersion = {
  None: 'none',
  V1: 'v1',
  V2: 'v2',
} as const;
export type ProxyProtocolVersion = (typeof ProxyProtocolVersion)[keyof typeof ProxyProtocolVersion];

export interface RelayEndpoint {
  targetHost: string;
  targetPort: number;
  weight: number;
  isAlive: boolean;
  activeConnections: number;
  totalBytesRelayed: number;
}

export class ZeroCopyRelaySupervisor {
  private endpoints: RelayEndpoint[] = [];
  private endpointIndex = 0;
  private sessions: Map<number, RelayEndpoint> = new Map();
  private nextSessionId = 1;
  public listenPort: number;
  public proxyProtocol: ProxyProtocolVersion;
  constructor(listenPort: number, proxyProtocol: ProxyProtocolVersion) {
    this.listenPort = listenPort;
    this.proxyProtocol = proxyProtocol;
  }

  addEndpoint(ep: RelayEndpoint): void {
    this.endpoints.push(ep);
  }

  openSession(): { sessionId: number; target: RelayEndpoint } | null {
    const healthy = this.endpoints.filter((e) => e.isAlive);
    if (healthy.length === 0) return null;

    const chosen = healthy[this.endpointIndex % healthy.length]!;
    this.endpointIndex++;
    chosen.activeConnections++;

    const sid = this.nextSessionId++;
    this.sessions.set(sid, chosen);
    return { sessionId: sid, target: chosen };
  }

  closeSession(sessionId: number, bytesRelayed: number): void {
    const ep = this.sessions.get(sessionId);
    if (ep) {
      if (ep.activeConnections > 0) ep.activeConnections--;
      ep.totalBytesRelayed += bytesRelayed;
      this.sessions.delete(sessionId);
    }
  }

  generateProxyHeader(
    clientIp: string,
    clientPort: number,
    serverIp: string,
    serverPort: number,
  ): Uint8Array {
    if (this.proxyProtocol === ProxyProtocolVersion.V1) {
      const family = clientIp.includes(':') ? 'TCP6' : 'TCP4';
      const str = `PROXY ${family} ${clientIp} ${serverIp} ${clientPort} ${serverPort}\r\n`;
      return new TextEncoder().encode(str);
    }
    return new Uint8Array(0);
  }
}
