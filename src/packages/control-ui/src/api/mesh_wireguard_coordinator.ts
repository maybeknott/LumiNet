// Control UI TypeScript: WireGuard Mesh Coordinator API

export type MeshConnectionMode = 'direct' | 'derp_relay';

export interface MeshPeer {
  peerId: string;
  publicKeyHex: string;
  virtualIp: string;
  allowedIps: string[];
  endpoints: string[];
  derpRegionId: number;
  lastHandshakeMs: number;
  isExitNode: boolean;
}

export class MeshWireguardCoordinator {
  public localPeerId: string;
  public localVirtualIp: string;
  public peers: Map<string, MeshPeer> = new Map();
  public derpRelays: Map<number, string> = new Map();

  constructor(localPeerId: string, localVirtualIp: string) {
    this.localPeerId = localPeerId;
    this.localVirtualIp = localVirtualIp;
  }

  public registerDerpRelay(regionId: number, hostname: string): void {
    this.derpRelays.set(regionId, hostname);
  }

  public registerPeer(peer: MeshPeer): void {
    this.peers.set(peer.peerId, peer);
  }

  public selectBestEndpoint(
    peerId: string,
    nowMs: number,
  ): { mode: MeshConnectionMode; endpoint: string } | null {
    const peer = this.peers.get(peerId);
    if (!peer) return null;

    const isRecent = nowMs - peer.lastHandshakeMs < 180_000;
    if (isRecent && peer.endpoints.length > 0) {
      return { mode: 'direct', endpoint: peer.endpoints[0]! };
    }

    if (this.derpRelays.has(peer.derpRegionId)) {
      return {
        mode: 'derp_relay',
        endpoint: this.derpRelays.get(peer.derpRegionId)!,
      };
    }

    if (peer.endpoints.length > 0) {
      return { mode: 'direct', endpoint: peer.endpoints[0]! };
    }

    return null;
  }

  public lookupRoute(destIp: string): string | null {
    for (const [id, peer] of this.peers.entries()) {
      if (peer.virtualIp === destIp) return id;
    }

    for (const [id, peer] of this.peers.entries()) {
      for (const cidr of peer.allowedIps) {
        if (this.isIpInCidr(destIp, cidr)) return id;
      }
    }

    return null;
  }

  public generateWireguardConfig(peerId: string): string {
    const peer = this.peers.get(peerId);
    if (!peer) throw new Error(`Peer not found: ${peerId}`);

    const allowed =
      peer.allowedIps.length > 0 ? peer.allowedIps.join(', ') : `${peer.virtualIp}/32`;
    const lines = ['[Peer]', `PublicKey = ${peer.publicKeyHex}`, `AllowedIPs = ${allowed}`];
    if (peer.endpoints.length > 0) {
      lines.push(`Endpoint = ${peer.endpoints[0]}`);
      lines.push('PersistentKeepalive = 25');
    }
    return lines.join('\n');
  }

  private isIpInCidr(ip: string, cidr: string): boolean {
    const [netStr, prefixStr] = cidr.split('/');
    if (!netStr || !prefixStr) return false;
    const prefix = parseInt(prefixStr, 10);
    const ipNum = this.ipToNumber(ip);
    const netNum = this.ipToNumber(netStr);
    const mask = prefix === 0 ? 0 : (~0 << (32 - prefix)) >>> 0;
    return (ipNum & mask) === (netNum & mask);
  }

  private ipToNumber(ip: string): number {
    return ip.split('.').reduce((acc, octet) => ((acc << 8) + parseInt(octet, 10)) >>> 0, 0);
  }
}
