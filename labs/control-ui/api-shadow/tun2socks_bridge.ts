/**
 * Tun2Socks Virtual Router & BadVPN UDP Gateway (udpgw) Interface API.
 *
 * Provides control UI interfaces and packet routing framing utilities for
 * userspace TUN-to-SOCKS5 redirection, transparent DNS capture, and UDPGW protocol multiplexing.
 *
 * Conforms to strict architectural isolation rules: zero vendor prefixes.
 */

export const UDPGW_CLIENT_FLAG_IPV6 = 0x01;
export const UDPGW_CLIENT_FLAG_DNS = 0x02;
export const DEFAULT_TUN_MTU = 1500;

export interface Tun2SocksConfig {
  vpnInterfaceFd: number;
  vpnInterfaceMTU: number;
  vpnIpv4Address: string;
  vpnIpv4NetMask: string;
  vpnIpv6Address?: string;
  socksServerAddress: string;
  udpgwServerAddress: string;
  udpgwTransparentDNS: boolean;
}

export interface Tun2SocksRouterStats {
  running: boolean;
  activeSessionsCount: number;
  packetsForwarded: number;
  bytesTx: number;
  bytesRx: number;
  dnsQueriesIntercepted: number;
  lastActiveAt: number;
}

export interface UdpGwFrameDto {
  flags: number;
  remoteIp: string;
  remotePort: number;
  payload: Uint8Array;
}

/** Parses an IPv6 address string into 16 bytes (full form only). */
function parseIpv6(ip: string): Uint8Array {
  const parts: number[] = [];
  for (const group of ip.split(':')) {
    const v = parseInt(group, 16) || 0;
    parts.push((v >> 8) & 0xff, v & 0xff);
  }
  return new Uint8Array(parts);
}

/**
 * Encodes a UDP payload into BadVPN UDPGW wire frame format.
 */
export function encodeUdpGwFrame(frame: UdpGwFrameDto): Uint8Array {
  const isV6 = frame.remoteIp.includes(':');
  const ipParts = isV6 ? parseIpv6(frame.remoteIp) : parseIpv4(frame.remoteIp);
  const totalLen = 1 + ipParts.length + 2 + frame.payload.length;
  const out = new Uint8Array(totalLen);

  let flags = frame.flags;
  if (isV6) {
    flags |= UDPGW_CLIENT_FLAG_IPV6;
  }
  out[0] = flags;
  out.set(ipParts, 1);

  const portOffset = 1 + ipParts.length;
  out[portOffset] = (frame.remotePort >> 8) & 0xff;
  out[portOffset + 1] = frame.remotePort & 0xff;
  out.set(frame.payload, portOffset + 2);
  return out;
}

/**
 * Decodes a BadVPN UDPGW wire frame.
 */
export function decodeUdpGwFrame(buf: Uint8Array): UdpGwFrameDto {
  if (buf.length < 7) {
    throw new Error('UDPGW frame buffer too short');
  }
  const flags = buf[0]!;
  const isV6 = (flags & UDPGW_CLIENT_FLAG_IPV6) !== 0;
  const ipLen = isV6 ? 16 : 4;

  if (buf.length < 1 + ipLen + 2) {
    throw new Error('UDPGW frame truncated');
  }

  const ipBytes = buf.subarray(1, 1 + ipLen);
  const remoteIp = isV6 ? formatIpv6(ipBytes) : formatIpv4(ipBytes);

  const portOffset = 1 + ipLen;
  const remotePort = (buf[portOffset]! << 8) | buf[portOffset + 1]!;
  const payload = buf.slice(portOffset + 2);

  return { flags, remoteIp, remotePort, payload };
}

function parseIpv4(ip: string): Uint8Array {
  const parts = ip.split('.').map((p) => parseInt(p, 10));
  if (parts.length !== 4 || parts.some((p) => isNaN(p) || p < 0 || p > 255)) {
    throw new Error(`Invalid IPv4 address: ${ip}`);
  }
  return new Uint8Array(parts);
}

function formatIpv4(octets: Uint8Array): string {
  return `${octets[0]}.${octets[1]}.${octets[2]}.${octets[3]}`;
}

function formatIpv6(octets: Uint8Array): string {
  const groups: string[] = [];
  for (let i = 0; i < 16; i += 2) {
    groups.push(((octets[i]! << 8) | octets[i + 1]!).toString(16));
  }
  return groups.join(':');
}

/**
 * Client API for controlling the Tun2Socks router subsystem.
 */
export class Tun2SocksClient {
  private baseUrl: string;

  constructor(baseUrl = '/api/v1/tunnel/tun2socks') {
    this.baseUrl = baseUrl;
  }

  async getStatus(): Promise<Tun2SocksRouterStats> {
    const res = await fetch(`${this.baseUrl}/status`);
    if (!res.ok) {
      throw new Error(`Failed to get Tun2Socks status: ${res.statusText}`);
    }
    return res.json();
  }

  async startRouter(config: Tun2SocksConfig): Promise<{ success: boolean; routerId: string }> {
    const res = await fetch(`${this.baseUrl}/start`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify(config),
    });
    if (!res.ok) {
      throw new Error(`Failed to start Tun2Socks router: ${res.statusText}`);
    }
    return res.json();
  }

  async stopRouter(): Promise<{ success: boolean }> {
    const res = await fetch(`${this.baseUrl}/stop`, { method: 'POST' });
    if (!res.ok) {
      throw new Error(`Failed to stop Tun2Socks router: ${res.statusText}`);
    }
    return res.json();
  }
}
