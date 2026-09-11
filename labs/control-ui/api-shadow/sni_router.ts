/**
 * SNI Domain Routing Table & Destination IP Rewriting API.
 *
 * Ported and unified from `smartSNI-main`.
 * Maps domain patterns to dedicated target IP addresses to bypass SNI filtering.
 *
 * Conforms to strict architectural isolation rules: zero vendor prefixes.
 */

export interface SniRouteRule {
  id: string;
  pattern: string;
  targetIp: string;
  type: 'exact' | 'wildcard' | 'substring';
  enabled: boolean;
  priority: number;
}

export interface SniRoutingTableDto {
  rules: SniRouteRule[];
  totalRoutes: number;
}

/**
 * Resolves target IP by applying exact -> wildcard -> substring precedence.
 */
export function resolveSniRoute(rules: SniRouteRule[], domain: string): string | null {
  const clean = domain.trim().replace(/\.+$/, '').toLowerCase();
  const activeRules = rules.filter((r) => r.enabled);

  // 1. Exact matches
  for (const r of activeRules) {
    if (r.type === 'exact') {
      const p = r.pattern.trim().replace(/\.+$/, '').toLowerCase();
      if (clean === p) {
        return r.targetIp;
      }
    }
  }

  // 2. Wildcard matches
  for (const r of activeRules) {
    if (r.type === 'wildcard') {
      let suffix = r.pattern.trim().toLowerCase();
      suffix = suffix.replace(/^\*+\.?/, '').replace(/\.+$/, '');
      if (clean === suffix || clean.endsWith(`.${suffix}`)) {
        return r.targetIp;
      }
    }
  }

  // 3. Substring matches
  for (const r of activeRules) {
    if (r.type === 'substring') {
      const substr = r.pattern.trim().toLowerCase();
      if (clean.includes(substr)) {
        return r.targetIp;
      }
    }
  }

  return null;
}

/**
 * Client API for SNI routing table management.
 */
export class SniRouterClient {
  private baseUrl: string;

  constructor(baseUrl = '/api/v1/dns/sni-router') {
    this.baseUrl = baseUrl;
  }

  async getRoutingTable(): Promise<SniRoutingTableDto> {
    const res = await fetch(`${this.baseUrl}/routes`);
    if (!res.ok) {
      throw new Error(`Failed to fetch SNI routes: ${res.statusText}`);
    }
    return res.json();
  }

  async addRoute(rule: Omit<SniRouteRule, 'id'>): Promise<SniRouteRule> {
    const res = await fetch(`${this.baseUrl}/routes`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify(rule),
    });
    if (!res.ok) {
      throw new Error(`Failed to add SNI route: ${res.statusText}`);
    }
    return res.json();
  }

  async deleteRoute(routeId: string): Promise<{ success: boolean }> {
    const res = await fetch(`${this.baseUrl}/routes/${routeId}`, { method: 'DELETE' });
    if (!res.ok) {
      throw new Error(`Failed to delete SNI route: ${res.statusText}`);
    }
    return res.json();
  }
}
