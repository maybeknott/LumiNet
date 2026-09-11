/**
 * Multi-Stage SOCKS5 Edge Diagnostics & Cloudflare Trace Engine.
 *
 * Ported and unified from `oblivion-main`.
 * Provides wire-level SOCKS5 framing, adaptive timeout ladders for validation stages,
 * and parsing of edge trace endpoint diagnostics (/cdn-cgi/trace).
 */

export interface CloudflareTraceInfo {
  colo?: string | undefined;
  loc?: string | undefined;
  ip?: string | undefined;
  warp?: string | undefined;
  visitScheme?: string | undefined;
  isWarpOk: boolean;
  rawEntries?: Record<string, string>;
}

export interface AttemptStage {
  attemptIndex: number;
  label: string;
  budgetSec: number;
  endpoint: string;
}

export interface SocksProbeConfig {
  mode: 'turbo' | 'standard' | 'stealth' | 'thorough' | string;
  endpoint: string;
  fastFirstConnect: boolean;
  isPsiphon: boolean;
  traceEndpoint?: string;
}

export const SOCKS_VERSION = 0x05;
export const CMD_CONNECT = 0x01;
export const ATYP_IPV4 = 0x01;
export const ATYP_DOMAIN = 0x03;
export const ATYP_IPV6 = 0x04;

/**
 * Calculates validation budget in seconds based on prober profile.
 */
export function calculateValidationBudget(mode: string): number {
  switch (mode.toLowerCase().trim()) {
    case 'turbo':
      return 105;
    case 'thorough':
      return 360;
    case 'stealth':
      return 240;
    case 'standard':
    default:
      return 180;
  }
}

/**
 * Builds the attempt ladder stages according to prober flags.
 */
export function buildAttempts(
  mode: string,
  endpoint: string,
  fastFirstConnect: boolean,
  isPsiphon: boolean,
): AttemptStage[] {
  const budget = calculateValidationBudget(mode);

  if (isPsiphon) {
    return [
      {
        attemptIndex: 0,
        label: 'configured',
        budgetSec: budget,
        endpoint,
      },
    ];
  }

  const stages: AttemptStage[] = [];
  let idx = 0;

  if (fastFirstConnect) {
    stages.push({
      attemptIndex: idx++,
      label: 'fast',
      budgetSec: 30,
      endpoint,
    });
  }

  stages.push({
    attemptIndex: idx,
    label: 'configured',
    budgetSec: budget,
    endpoint,
  });

  return stages;
}

/**
 * Parses /cdn-cgi/trace response body into structured CloudflareTraceInfo.
 */
export function parseTraceBody(body: string): CloudflareTraceInfo {
  const entries: Record<string, string> = {};
  const lines = body.split(/\r?\n/);

  for (const line of lines) {
    const trimmed = line.trim();
    const eqIdx = trimmed.indexOf('=');
    if (eqIdx > 0) {
      const key = trimmed.substring(0, eqIdx).trim();
      const val = trimmed.substring(eqIdx + 1).trim();
      entries[key] = val;
    }
  }

  const warp = entries['warp'];
  const isWarpOk = warp === 'on' || warp === 'plus';

  return {
    colo: entries['colo'],
    loc: entries['loc'],
    ip: entries['ip'],
    warp: entries['warp'],
    visitScheme: entries['visit_scheme'],
    isWarpOk,
    rawEntries: entries,
  };
}

/**
 * Builds SOCKS5 greeting handshake frame.
 */
export function buildGreeting(authMethods: number[] = [0x00]): Uint8Array {
  const buf = new Uint8Array(2 + authMethods.length);
  buf[0] = SOCKS_VERSION;
  buf[1] = authMethods.length;
  for (let i = 0; i < authMethods.length; i++) {
    buf[2 + i] = authMethods[i]!;
  }
  return buf;
}

/**
 * Verifies SOCKS5 greeting response frame.
 */
export function verifyGreetingReply(reply: Uint8Array): number {
  if (reply.length < 2) {
    throw new Error(`SOCKS greeting reply too short: ${reply.length} < 2`);
  }
  if (reply[0] !== SOCKS_VERSION) {
    throw new Error(`Invalid SOCKS version in greeting reply: ${reply[0]}`);
  }
  if (reply[1] === 0xff) {
    throw new Error('SOCKS server rejected authentication methods');
  }
  return reply[1]!;
}

/**
 * Builds SOCKS5 CONNECT command frame targeting an IPv4 address.
 */
export function buildConnectIpv4(ipBytes: number[], port: number): Uint8Array {
  if (ipBytes.length !== 4) {
    throw new Error('IPv4 address must be exactly 4 bytes');
  }
  const buf = new Uint8Array(10);
  buf[0] = SOCKS_VERSION;
  buf[1] = CMD_CONNECT;
  buf[2] = 0x00; // Reserved
  buf[3] = ATYP_IPV4;
  buf[4] = ipBytes[0]!;
  buf[5] = ipBytes[1]!;
  buf[6] = ipBytes[2]!;
  buf[7] = ipBytes[3]!;
  buf[8] = (port >> 8) & 0xff;
  buf[9] = port & 0xff;
  return buf;
}

/**
 * Builds SOCKS5 CONNECT command frame targeting a domain string.
 */
export function buildConnectDomain(domain: string, port: number): Uint8Array {
  const encoder = new TextEncoder();
  const domainBytes = encoder.encode(domain);
  if (domainBytes.length > 255) {
    throw new Error(`Domain name too long for SOCKS5: ${domain.length}`);
  }

  const totalLen = 4 + 1 + domainBytes.length + 2;
  const buf = new Uint8Array(totalLen);
  buf[0] = SOCKS_VERSION;
  buf[1] = CMD_CONNECT;
  buf[2] = 0x00; // Reserved
  buf[3] = ATYP_DOMAIN;
  buf[4] = domainBytes.length;
  buf.set(domainBytes, 5);

  const portOffset = 5 + domainBytes.length;
  buf[portOffset] = (port >> 8) & 0xff;
  buf[portOffset + 1] = port & 0xff;
  return buf;
}

/**
 * Verifies SOCKS5 CONNECT response frame.
 */
export function verifyConnectReply(reply: Uint8Array): void {
  if (reply.length < 4) {
    throw new Error(`SOCKS connect reply too short: ${reply.length} < 4`);
  }
  if (reply[0] !== SOCKS_VERSION) {
    throw new Error(`Invalid SOCKS version in connect reply: ${reply[0]}`);
  }

  const rep = reply[1]!;
  if (rep !== 0x00) {
    const errMap: Record<number, string> = {
      0x01: 'general SOCKS server failure',
      0x02: 'connection not allowed by ruleset',
      0x03: 'network unreachable',
      0x04: 'host unreachable',
      0x05: 'connection refused',
      0x06: 'TTL expired',
      0x07: 'command not supported',
      0x08: 'address type not supported',
    };
    throw new Error(`SOCKS connect error: ${errMap[rep] || `code 0x${rep.toString(16)}`}`);
  }
}
