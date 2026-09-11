export interface WireguardPeer {
  publicKey: string;
  assignedIp: string;
  allowedIps: string[];
  endpoint?: string;
  enabled: boolean;
}

export class WireguardIpamManager {
  private subnetPrefix: string;
  private nextIpSuffix: number = 2;
  public serverIp: string;
  public listenPort: number;
  private peers: Map<string, WireguardPeer> = new Map();
  private ipToKey: Map<string, string> = new Map();

  constructor(subnetPrefix: string, listenPort: number) {
    const parts = subnetPrefix.split('.');
    if (parts.length !== 3) {
      throw new Error('Subnet prefix must have 3 octets, e.g. 10.14.0');
    }
    this.subnetPrefix = subnetPrefix;
    this.serverIp = `${subnetPrefix}.1`;
    this.listenPort = listenPort;
  }

  allocatePeer(publicKey: string): WireguardPeer {
    const existing = this.peers.get(publicKey);
    if (existing) {
      return { ...existing };
    }

    if (this.nextIpSuffix >= 254) {
      throw new Error('Subnet exhausted');
    }

    const assignedIp = `${this.subnetPrefix}.${this.nextIpSuffix}`;
    this.nextIpSuffix += 1;

    const peer: WireguardPeer = {
      publicKey,
      assignedIp,
      allowedIps: [`${assignedIp}/32`],
      enabled: true,
    };

    this.ipToKey.set(assignedIp, publicKey);
    this.peers.set(publicKey, peer);
    return { ...peer };
  }

  releasePeer(publicKey: string): void {
    const peer = this.peers.get(publicKey);
    if (!peer) {
      throw new Error('Peer not found');
    }
    this.ipToKey.delete(peer.assignedIp);
    this.peers.delete(publicKey);
  }

  getPeer(publicKey: string): WireguardPeer | undefined {
    const p = this.peers.get(publicKey);
    return p ? { ...p } : undefined;
  }

  generateServerConfig(serverPrivateKey: string): string {
    const lines: string[] = [];
    lines.push('[Interface]');
    lines.push(`Address = ${this.serverIp}/24`);
    lines.push(`ListenPort = ${this.listenPort}`);
    lines.push(`PrivateKey = ${serverPrivateKey}`);
    lines.push('');

    for (const peer of this.peers.values()) {
      if (peer.enabled) {
        lines.push('[Peer]');
        lines.push(`PublicKey = ${peer.publicKey}`);
        lines.push(`AllowedIPs = ${peer.allowedIps.join(', ')}`);
        if (peer.endpoint) {
          lines.push(`Endpoint = ${peer.endpoint}`);
        }
        lines.push('');
      }
    }

    return lines.join('\n');
  }

  generateClientConfig(
    peerPublicKey: string,
    peerPrivateKey: string,
    serverPublicKey: string,
    serverEndpoint: string
  ): string {
    const peer = this.peers.get(peerPublicKey);
    if (!peer) {
      throw new Error('Peer not registered');
    }

    const lines: string[] = [];
    lines.push('[Interface]');
    lines.push(`Address = ${peer.assignedIp}/32`);
    lines.push(`PrivateKey = ${peerPrivateKey}`);
    lines.push('DNS = 1.1.1.1');
    lines.push('');

    lines.push('[Peer]');
    lines.push(`PublicKey = ${serverPublicKey}`);
    lines.push(`Endpoint = ${serverEndpoint}`);
    lines.push('AllowedIPs = 0.0.0.0/0, ::/0');
    lines.push('PersistentKeepalive = 25');

    return lines.join('\n');
  }
}
