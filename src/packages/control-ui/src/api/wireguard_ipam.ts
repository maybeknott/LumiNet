export interface WireguardPeerRecord {
  publicKey: string;
  presharedKey: string;
  allocatedV4: string;
  allocatedV6: string;
  name: string;
  enabled: boolean;
}

export class WireguardIpam {
  private nextHostId = 2;
  private readonly peers = new Map<string, WireguardPeerRecord>();
  private readonly v4BasePrefix: string;
  private readonly v6BasePrefix: string;
  constructor(v4BasePrefix: string = '10.88.0.', v6BasePrefix: string = 'fd00:88::') {
    this.v4BasePrefix = v4BasePrefix;
    this.v6BasePrefix = v6BasePrefix;
  }

  public allocatePeer(publicKey: string, name: string): WireguardPeerRecord {
    const existing = this.peers.get(publicKey);
    if (existing) return existing;

    const v4 = `${this.v4BasePrefix}${this.nextHostId}`;
    const v6 = `${this.v6BasePrefix}${this.nextHostId}`;
    this.nextHostId++;

    const record: WireguardPeerRecord = {
      publicKey,
      presharedKey: 'mockPskBase64==',
      allocatedV4: v4,
      allocatedV6: v6,
      name,
      enabled: true,
    };
    this.peers.set(publicKey, record);
    return record;
  }

  public formatClientConfig(
    rec: WireguardPeerRecord,
    clientPrivKey: string,
    endpoint: string,
    serverPubKey: string,
    dns = '1.1.1.1',
  ): string {
    return `[Interface]
    PrivateKey = ${clientPrivKey}
    Address = ${rec.allocatedV4}/32, ${rec.allocatedV6}/128
    DNS = ${dns}

    [Peer]
    PublicKey = ${serverPubKey}
    PresharedKey = ${rec.presharedKey}
    Endpoint = ${endpoint}
    AllowedIPs = 0.0.0.0/0, ::/0
    PersistentKeepalive = 25
    `;
  }
}
