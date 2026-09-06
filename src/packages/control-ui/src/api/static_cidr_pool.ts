export interface StaticClientRecord {
  clientId: string;
  allocatedIp: string;
  publicKey: string;
  isRevoked: boolean;
}

export class StaticCidrPool {
  private nextHost = 2;
  private readonly allocated = new Map<string, StaticClientRecord>();
  private readonly revokedKeys = new Set<string>();
  private readonly basePrefix;
  constructor(basePrefix = '10.66.0.') {
    this.basePrefix = basePrefix;
  }

  public allocateClient(clientId: string, publicKey: string): StaticClientRecord | null {
    if (this.nextHost >= 254) return null;
    const ip = `${this.basePrefix}${this.nextHost}`;
    this.nextHost++;

    const record: StaticClientRecord = {
      clientId,
      allocatedIp: ip,
      publicKey,
      isRevoked: false,
    };
    this.allocated.set(ip, record);
    return record;
  }

  public revokeClient(ip: string): boolean {
    const client = this.allocated.get(ip);
    if (!client) return false;
    client.isRevoked = true;
    this.revokedKeys.add(client.publicKey);
    return true;
  }

  public isKeyRevoked(publicKey: string): boolean {
    return this.revokedKeys.has(publicKey);
  }
}
