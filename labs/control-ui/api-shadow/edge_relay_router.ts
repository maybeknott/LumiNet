/**
 * Edge Serverless Relay Router & Cloudflare Loopback Evasion API.
 *
 * Ported and unified from `bepass-worker-main`.
 * Provides edge route decisions (direct vs chained relay), session hash balancing,
 * Cloudflare CIDR loopback detection, and RFC 8484 DNS wire query synthesis.
 */

import { ipv4MatchesCidr } from './relay_acl_filter';

export const DEFAULT_RELAY_HOSTS: string[] = [
  'relay1.bepass.org',
  'relay2.bepass.org',
  'relay3.bepass.org',
];

export const CANONICAL_CF_IPV4: string[] = [
  '173.245.48.0/20',
  '103.21.244.0/22',
  '103.22.200.0/22',
  '103.31.4.0/22',
  '141.101.64.0/18',
  '108.162.192.0/18',
  '190.93.240.0/20',
  '188.114.96.0/20',
  '197.234.240.0/22',
  '198.41.128.0/17',
  '162.158.0.0/15',
  '104.16.0.0/13',
  '104.24.0.0/14',
  '172.64.0.0/13',
  '131.0.72.0/22',
];

export const CANONICAL_CF_IPV6: string[] = [
  '2400:cb00::/32',
  '2606:4700::/32',
  '2803:f800::/32',
  '2405:b500::/32',
  '2405:8100::/32',
  '2a06:98c0::/29',
  '2c0f:f248::/32',
];

export interface EdgeRouteTarget {
  network: 'tcp' | 'udp';
  host: string;
  port: number;
  resolvedIp?: string;
}

export interface EdgeRoutingDecision {
  isRelayChained: boolean;
  targetHost: string;
  targetPort: number;
  relayHost?: string;
  relayPort?: number;
  delimiterHeader?: string;
}

export class EdgeRelayRouter {
  private relayHosts: string[];
  private relayPort: number;
  private cloudflareCidrs: string[];

  constructor(
    relayHosts: string[] = DEFAULT_RELAY_HOSTS,
    relayPort: number = 6666,
    cloudflareCidrs: string[] = [...CANONICAL_CF_IPV4, ...CANONICAL_CF_IPV6],
  ) {
    this.relayHosts = [...relayHosts];
    this.relayPort = relayPort;
    this.cloudflareCidrs = [...cloudflareCidrs];
  }

  public selectRelayEndpoint(sessionId?: number): {
    host: string;
    port: number;
  } {
    if (this.relayHosts.length === 0) {
      return { host: '127.0.0.1', port: this.relayPort };
    }
    const idx = sessionId !== undefined ? Math.abs(sessionId) % this.relayHosts.length : 0;
    return { host: this.relayHosts[idx]!, port: this.relayPort };
  }

  public isCloudflareIp(ip?: string): boolean {
    if (!ip) return false;
    return this.cloudflareCidrs.some((cidr) => ipv4MatchesCidr(ip, cidr));
  }

  public decideRoute(target: EdgeRouteTarget, sessionId?: number): EdgeRoutingDecision {
    const netLower = target.network.toLowerCase();
    const requiresRelay = netLower === 'udp' || this.isCloudflareIp(target.resolvedIp);

    if (requiresRelay) {
      const { host: relayHost, port: relayPort } = this.selectRelayEndpoint(sessionId);
      const header = `${netLower}@${target.host}$${target.port}\r\n`;
      return {
        isRelayChained: true,
        targetHost: target.host,
        targetPort: target.port,
        relayHost,
        relayPort,
        delimiterHeader: header,
      };
    }

    return {
      isRelayChained: false,
      targetHost: target.host,
      targetPort: target.port,
    };
  }

  public buildFallbackRelayRoute(target: EdgeRouteTarget, sessionId?: number): EdgeRoutingDecision {
    const netLower = target.network.toLowerCase();
    const { host: relayHost, port: relayPort } = this.selectRelayEndpoint(sessionId);
    const header = `${netLower}@${target.host}$${target.port}\r\n`;
    return {
      isRelayChained: true,
      targetHost: target.host,
      targetPort: target.port,
      relayHost,
      relayPort,
      delimiterHeader: header,
    };
  }

  public static buildDohAQuery(domain: string): Uint8Array {
    const parts = domain.split('.');
    const labels: number[] = [];
    const encoder = new TextEncoder();

    for (const p of parts) {
      if (p.length > 0) {
        const encoded = encoder.encode(p);
        labels.push(encoded.length, ...encoded);
      }
    }
    labels.push(0x00);

    const query = new Uint8Array(12 + labels.length + 4);
    // Header
    query.set(
      [
        0x12,
        0x34, // Transaction ID
        0x01,
        0x00, // Standard query
        0x00,
        0x01, // Questions: 1
        0x00,
        0x00, // Answers: 0
        0x00,
        0x00, // Authority: 0
        0x00,
        0x00, // Additional: 0
      ],
      0,
    );

    // QNAME
    query.set(labels, 12);

    // QTYPE (1) and QCLASS (1)
    const offset = 12 + labels.length;
    query.set([0x00, 0x01, 0x00, 0x01], offset);

    return query;
  }
}
