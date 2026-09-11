export interface IdentitySessionData {
  email: string;
  domain: string;
  groups: string[];
}

export interface RoutePolicyRule {
  pathPrefix: string;
  allowedDomains?: string[];
  requiredGroups?: string[];
}

export class IdentityPolicyEvaluator {
  private readonly policies: RoutePolicyRule[] = [];

  public addPolicy(rule: RoutePolicyRule): void {
    this.policies.push(rule);
  }

  public isAuthorized(path: string, session: IdentitySessionData): boolean {
    for (const policy of this.policies) {
      if (path.startsWith(policy.pathPrefix)) {
        if (policy.allowedDomains && policy.allowedDomains.length > 0) {
          if (!policy.allowedDomains.includes(session.domain)) {
            return false;
          }
        }
        if (policy.requiredGroups && policy.requiredGroups.length > 0) {
          const hasGroup = policy.requiredGroups.some(g => session.groups.includes(g));
          if (!hasGroup) {
            return false;
          }
        }
        return true;
      }
    }
    return false;
  }
}
