export type UserRole = 'guest' | 'operator' | 'admin';

const roleRank: Record<UserRole, number> = {
  guest: 0,
  operator: 1,
  admin: 2,
};

export class AccessInterceptor {
  private routeRoles = new Map<string, UserRole>();
  public auditCount = 0;

  protectRoute(prefix: string, minRole: UserRole): void {
    this.routeRoles.set(prefix, minRole);
  }

  authorize(path: string, role: UserRole): boolean {
    this.auditCount++;
    for (const [prefix, minRole] of this.routeRoles.entries()) {
      if (path.startsWith(prefix)) {
        if (roleRank[role] < roleRank[minRole]) return false;
      }
    }
    return true;
  }
}
