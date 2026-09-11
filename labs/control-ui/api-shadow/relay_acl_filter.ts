/**
 * Relay Access Control List (ACL) Filter & UDP-over-TCP Multiplexing API.
 *
 * Ported and unified from `bepass-relay-main`.
 * Guards ingress with Cloudflare edge CIDR whitelist, prohibits abusive tracker/localhost egress,
 * and handles 8-byte session framed UDP-over-TCP multiplexing.
 */

export const DEFAULT_EDGE_CIDRS: string[] = [
  '103.21.244.0/22',
  '103.22.200.0/22',
  '103.31.4.0/22',
  '104.16.0.0/12',
  '108.162.192.0/18',
  '131.0.72.0/22',
  '141.101.64.0/18',
  '162.158.0.0/15',
  '172.64.0.0/13',
  '173.245.48.0/20',
  '188.114.96.0/20',
  '190.93.240.0/20',
  '197.234.240.0/22',
  '198.41.128.0/17',
  '2400:cb00::/32',
  '2405:8100::/32',
  '2405:b500::/32',
  '2606:4700::/32',
  '2803:f800::/32',
  '2c0f:f248::/32',
  '2a06:98c0::/29',
];

export const DEFAULT_BLOCKED_CIDRS: string[] = [
  '127.0.0.0/8',
  '::1/128',
  '93.158.213.92/32',
  '102.223.180.235/32',
  '23.134.88.6/32',
  '185.243.218.213/32',
  '208.83.20.20/32',
  '91.216.110.52/32',
  '83.146.97.90/32',
  '23.157.120.14/32',
  '185.102.219.163/32',
  '163.172.29.130/32',
  '156.234.201.18/32',
  '209.141.59.16/32',
  '34.94.213.23/32',
  '192.3.165.191/32',
  '130.61.55.93/32',
  '109.201.134.183/32',
  '95.31.11.224/32',
  '83.102.180.21/32',
  '192.95.46.115/32',
  '198.100.149.66/32',
  '95.216.74.39/32',
  '51.68.174.87/32',
  '37.187.111.136/32',
  '51.15.79.209/32',
  '45.92.156.182/32',
  '49.12.76.8/32',
  '5.196.89.204/32',
  '62.233.57.13/32',
  '45.9.60.30/32',
  '35.227.12.84/32',
  '179.43.155.30/32',
  '94.243.222.100/32',
  '207.241.231.226/32',
  '207.241.226.111/32',
  '51.159.54.68/32',
  '82.65.115.10/32',
  '95.217.167.10/32',
  '86.57.161.157/32',
  '83.31.30.230/32',
  '94.103.87.87/32',
  '160.119.252.41/32',
  '193.42.111.57/32',
  '80.240.22.46/32',
  '107.189.31.134/32',
  '104.244.79.114/32',
  '85.239.33.28/32',
  '61.222.178.254/32',
  '38.7.201.142/32',
  '51.81.222.188/32',
  '103.196.36.31/32',
  '23.153.248.2/32',
  '73.170.204.100/32',
  '176.31.250.174/32',
  '149.56.179.233/32',
  '212.237.53.230/32',
  '185.68.21.244/32',
  '82.156.24.219/32',
  '216.201.9.155/32',
  '51.15.41.46/32',
  '85.206.172.159/32',
  '104.244.77.87/32',
  '37.27.4.53/32',
  '192.3.165.198/32',
  '15.204.205.14/32',
  '103.122.21.50/32',
  '104.131.98.232/32',
  '173.249.201.201/32',
  '23.254.228.89/32',
  '5.102.159.190/32',
  '65.130.205.148/32',
  '119.28.71.45/32',
  '159.69.65.157/32',
  '160.251.78.190/32',
  '107.189.7.143/32',
  '159.65.224.91/32',
  '185.217.199.21/32',
  '91.224.92.110/32',
  '161.97.67.210/32',
  '51.15.3.74/32',
  '209.126.11.233/32',
  '37.187.95.112/32',
  '167.99.185.219/32',
  '144.91.88.22/32',
  '88.99.2.212/32',
  '37.59.48.81/32',
  '95.179.130.187/32',
  '51.15.26.25/32',
  '192.9.228.30/32',
];

export function parseIpv4ToNumber(ip: string): number | null {
  const parts = ip.split('.');
  if (parts.length !== 4) return null;
  let num = 0;
  for (const part of parts) {
    const octet = parseInt(part, 10);
    if (isNaN(octet) || octet < 0 || octet > 255) return null;
    num = (num << 8) | octet;
  }
  return num >>> 0;
}

export function ipv4MatchesCidr(ip: string, cidr: string): boolean {
  const [rangeIp, prefixStr] = cidr.split('/');
  if (!rangeIp || !prefixStr) return false;
  const prefix = parseInt(prefixStr, 10);
  if (isNaN(prefix) || prefix < 0 || prefix > 32) return false;

  const targetNum = parseIpv4ToNumber(ip);
  const rangeNum = parseIpv4ToNumber(rangeIp);
  if (targetNum === null || rangeNum === null) return false;

  if (prefix === 0) return true;
  const mask = prefix === 32 ? 0xffffffff : ~((1 << (32 - prefix)) - 1) >>> 0;
  return (targetNum & mask) === (rangeNum & mask);
}

export class RelayAclFilter {
  private sourceWhitelist: string[];
  private destinationBlacklist: string[];

  constructor(
    sourceWhitelist: string[] = DEFAULT_EDGE_CIDRS,
    destinationBlacklist: string[] = DEFAULT_BLOCKED_CIDRS,
  ) {
    this.sourceWhitelist = [...sourceWhitelist];
    this.destinationBlacklist = [...destinationBlacklist];
  }

  public isSourceAllowed(ip: string): boolean {
    return this.sourceWhitelist.some((cidr) => ipv4MatchesCidr(ip, cidr));
  }

  public isDestinationAllowed(ip: string): boolean {
    return !this.destinationBlacklist.some((cidr) => ipv4MatchesCidr(ip, cidr));
  }

  public evaluate(src: string, dst: string): { allowed: boolean; reason?: string } {
    if (!this.isSourceAllowed(src)) {
      return {
        allowed: false,
        reason: `Source IP ${src} is not in authorized edge whitelist`,
      };
    }
    if (!this.isDestinationAllowed(dst)) {
      return {
        allowed: false,
        reason: `Destination IP ${dst} is in prohibited blacklist`,
      };
    }
    return { allowed: true };
  }
}

export interface UdpOverTcpFrame {
  sessionId: Uint8Array;
  streamTag: Uint8Array;
  payload: Uint8Array;
}

export class UdpOverTcpMultiplexer {
  public static encode(
    sessionId: Uint8Array,
    streamTag: Uint8Array,
    payload: Uint8Array,
  ): Uint8Array {
    const out = new Uint8Array(8 + payload.length);
    out.set(sessionId.subarray(0, 6), 0);
    out.set(streamTag.subarray(0, 2), 6);
    out.set(payload, 8);
    return out;
  }

  public static decode(src: Uint8Array): UdpOverTcpFrame | null {
    if (src.length < 8) return null;
    return {
      sessionId: src.slice(0, 6),
      streamTag: src.slice(6, 8),
      payload: src.slice(8),
    };
  }

  public static buildResponse(streamTag: Uint8Array, datagram: Uint8Array): Uint8Array {
    const out = new Uint8Array(2 + datagram.length);
    out.set(streamTag.subarray(0, 2), 0);
    out.set(datagram, 2);
    return out;
  }

  public static decodeResponse(
    src: Uint8Array,
  ): { streamTag: Uint8Array; datagram: Uint8Array } | null {
    if (src.length < 2) return null;
    return {
      streamTag: src.slice(0, 2),
      datagram: src.slice(2),
    };
  }

  public static channelKey(
    destination: string,
    sessionId: Uint8Array,
    streamTag: Uint8Array,
  ): string {
    const hex = (buf: Uint8Array) =>
      Array.from(buf)
        .map((b) => b.toString(16).padStart(2, '0'))
        .join('');
    return `${destination}:${hex(sessionId.subarray(0, 6))}${hex(streamTag.subarray(0, 2))}`;
  }
}
