export const EnterpriseUserRole = {
  StandardUser: 'STANDARD_USER',
  Admin: 'ADMIN',
  Auditor: 'AUDITOR',
} as const;
export type EnterpriseUserRole = (typeof EnterpriseUserRole)[keyof typeof EnterpriseUserRole];

export interface EnterpriseTenant {
  orgId: string;
  name: string;
  virtualSubnet: string;
  maxUsers: number;
}

export interface EnterpriseUserProfile {
  username: string;
  orgId: string;
  role: EnterpriseUserRole;
  token: string;
  virtualIp: string;
  allowedRoutes: string[];
  isActive?: boolean;
}

export class EnterpriseVpnController {
  private orgs: Map<string, EnterpriseTenant> = new Map();
  private users: Map<string, EnterpriseUserProfile> = new Map();

  registerTenant(tenant: EnterpriseTenant): void {
    this.orgs.set(tenant.orgId, tenant);
  }

  registerUser(user: EnterpriseUserProfile): boolean {
    const org = this.orgs.get(user.orgId);
    if (!org) return false;

    let activeCount = 0;
    for (const u of this.users.values()) {
      if (u.orgId === user.orgId && (u.isActive ?? true)) {
        activeCount++;
      }
    }
    if (activeCount >= org.maxUsers) return false;

    this.users.set(user.token, { ...user, isActive: true });
    return true;
  }

  authenticate(token: string): EnterpriseUserProfile | null {
    const u = this.users.get(token);
    if (!u || !u.isActive) return null;
    return u;
  }

  canAccessRoute(token: string, destinationIp: string): boolean {
    const u = this.authenticate(token);
    if (!u) return false;
    if (u.role === EnterpriseUserRole.Admin) return true;

    for (const route of u.allowedRoutes) {
      if (route === '0.0.0.0/0') return true;
      if (route.includes('/')) {
        const [netStr, prefixStr] = route.split('/');
        const prefix = parseInt(prefixStr!, 10);
        if (this.matchesCidr(destinationIp, netStr!, prefix)) {
          return true;
        }
      } else if (route === destinationIp) {
        return true;
      }
    }
    return false;
  }

  revokeUser(token: string): boolean {
    const u = this.users.get(token);
    if (!u) return false;
    u.isActive = false;
    return true;
  }

  activeUserCount(): number {
    let count = 0;
    for (const u of this.users.values()) {
      if (u.isActive ?? true) count++;
    }
    return count;
  }

  private matchesCidr(ip: string, net: string, prefix: number): boolean {
    const ipVal = this.ipToNumber(ip);
    const netVal = this.ipToNumber(net);
    if (ipVal === null || netVal === null) return false;
    const mask = prefix === 0 ? 0 : (~0 << (32 - prefix)) >>> 0;
    return (ipVal & mask) === (netVal & mask);
  }

  private ipToNumber(ip: string): number | null {
    const parts = ip.split('.');
    if (parts.length !== 4) return null;
    let res = 0;
    for (const p of parts) {
      const v = parseInt(p, 10);
      if (isNaN(v) || v < 0 || v > 255) return null;
      res = (res << 8) | v;
    }
    return res >>> 0;
  }
}
