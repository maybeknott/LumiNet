export interface ZeroTrustResource {
  id: string;
  name: string;
  networkCidr: string;
  mappedIp: string;
  allowedPermissionMask: number;
}

export class ZeroTrustRouteTable {
  private readonly resources = new Map<string, ZeroTrustResource>();
  private readonly ipToResource = new Map<string, string>();

  public registerResource(res: ZeroTrustResource): void {
    this.resources.set(res.id, res);
    this.ipToResource.set(res.mappedIp, res.id);
  }

  public lookupByIp(ip: string): ZeroTrustResource | null {
    const id = this.ipToResource.get(ip);
    if (!id) return null;
    return this.resources.get(id) ?? null;
  }

  public evaluateAccess(ip: string, clientPermissions: number): boolean {
    const res = this.lookupByIp(ip);
    if (!res) return false;
    return (res.allowedPermissionMask & clientPermissions) === res.allowedPermissionMask;
  }
}
