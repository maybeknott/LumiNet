/**
 * SNI Spoof Engine & DPI Desync Profile Definitions
 * Originates from SpoofGUI-master and ported into LumiNet Control UI.
 */

export interface SniSpoofEngineProfile {
  enabled: boolean;
  proxy_listen_port: number;
  fake_sni: string;
  cloudflare_decoy_enabled: boolean;
  kill_switch_enabled: boolean;
  kill_switch_grace_sec: number;
  allowed_cloudflares: string[];
  fragment_offset: number;
}

export const CLOUDFLARE_IPV4_CIDRS: readonly string[] = [
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

export const DEFAULT_SNI_SPOOF_ENGINE_PROFILE: SniSpoofEngineProfile = {
  enabled: true,
  proxy_listen_port: 8080,
  fake_sni: 'speed.cloudflare.com',
  cloudflare_decoy_enabled: true,
  kill_switch_enabled: false,
  kill_switch_grace_sec: 10,
  allowed_cloudflares: [...CLOUDFLARE_IPV4_CIDRS],
  fragment_offset: 2,
};

export type KillSwitchState = 'Disarmed' | 'Armed' | 'Tripped';

export interface KillSwitchStatus {
  state: KillSwitchState;
  firewall_rules_active: boolean;
  monitored_process_name: string;
  consecutive_failures: number;
}

/**
 * Strips protocols, paths, ports, comments and whitespace from a candidate domain string.
 */
export function cleanDomain(raw: string): string {
  let s = raw.trim();
  const commentIdx = s.indexOf(';');
  if (commentIdx !== -1) {
    s = s.substring(0, commentIdx).trim();
  }
  const hashIdx = s.indexOf('#');
  if (hashIdx !== -1) {
    s = s.substring(0, hashIdx).trim();
  }

  if (s.toLowerCase().startsWith('https://')) {
    s = s.substring(8);
  } else if (s.toLowerCase().startsWith('http://')) {
    s = s.substring(7);
  }

  const slashIdx = s.indexOf('/');
  if (slashIdx !== -1) {
    s = s.substring(0, slashIdx);
  }

  const colonIdx = s.indexOf(':');
  if (colonIdx !== -1) {
    s = s.substring(0, colonIdx);
  }

  return s.trim().toLowerCase();
}

/**
 * Parses an IPv4 string into a 32-bit unsigned number.
 */
export function parseIpv4(ip: string): number | null {
  const parts = ip.trim().split('.');
  if (parts.length !== 4) return null;
  let num = 0;
  for (const part of parts) {
    const p = parseInt(part, 10);
    if (isNaN(p) || p < 0 || p > 255) return null;
    num = (num << 8) | p;
  }
  return num >>> 0;
}

/**
 * Checks whether an IPv4 address belongs to known Cloudflare CIDR blocks.
 */
export function isCloudflareIpv4(ip: string, cidrs: readonly string[] = CLOUDFLARE_IPV4_CIDRS): boolean {
  const ipNum = parseIpv4(ip);
  if (ipNum === null) return false;

  for (const cidr of cidrs) {
    const [networkStr, prefixStr] = cidr.split('/');
    if (!networkStr || !prefixStr) continue;
    const netNum = parseIpv4(networkStr);
    const prefix = parseInt(prefixStr, 10);
    if (netNum === null || isNaN(prefix) || prefix < 0 || prefix > 32) continue;

    const mask = prefix === 0 ? 0 : ((0xffffffff << (32 - prefix)) >>> 0);
    if ((ipNum & mask) === (netNum & mask)) {
      return true;
    }
  }

  return false;
}

/**
 * Constructs a canonical 517-byte TLS ClientHello packet with RFC 7685 padding.
 */
export function buildTlsClientHelloFake(fakeSni: string): Uint8Array {
  const sniBytes = new TextEncoder().encode(fakeSni);
  const padLen = Math.max(0, 219 - sniBytes.length);

  const payload: number[] = [];

  // TLS Record Header: Handshake (0x16), TLS 1.0 (0x03, 0x01), Length (2 bytes later)
  payload.push(0x16, 0x03, 0x01, 0x00, 0x00);

  // Handshake Header: ClientHello (0x01), Handshake Length (3 bytes later)
  const handshakeStart = payload.length;
  payload.push(0x01, 0x00, 0x00, 0x00);

  // Client Version: TLS 1.2 (0x03, 0x03)
  payload.push(0x03, 0x03);

  // Random: 32 bytes
  for (let i = 0; i < 32; i++) {
    payload.push((i * 31 + 7) & 0xff);
  }

  // Session ID: len 32
  payload.push(0x20);
  for (let i = 0; i < 32; i++) {
    payload.push((i * 17 + 13) & 0xff);
  }

  // Cipher Suites (17 suites = 34 bytes)
  const suites: number[] = [
    0x13, 0x01, 0x13, 0x02, 0x13, 0x03, 0xc0, 0x2b, 0xc0, 0x2f, 0xc0, 0x2c, 0xc0, 0x30, 0xcc, 0xa9,
    0xcc, 0xa8, 0xc0, 0x13, 0xc0, 0x14, 0x00, 0x9c, 0x00, 0x9d, 0x00, 0x2f, 0x00, 0x35, 0x00, 0x0a,
  ];
  payload.push((suites.length >> 8) & 0xff, suites.length & 0xff);
  payload.push(...suites);

  // Compression Methods: 1 method (null: 0x00)
  payload.push(0x01, 0x00);

  // Extensions start
  const extLenPos = payload.length;
  payload.push(0x00, 0x00); // placeholder for extensions length

  const extensionsStart = payload.length;

  // Extension: Server Name Indication (0x0000)
  const sniExtDataLen = sniBytes.length + 5;
  payload.push(0x00, 0x00);
  payload.push((sniExtDataLen >> 8) & 0xff, sniExtDataLen & 0xff);
  const sniListLen = sniBytes.length + 3;
  payload.push((sniListLen >> 8) & 0xff, sniListLen & 0xff);
  payload.push(0x00); // HostName type
  payload.push((sniBytes.length >> 8) & 0xff, sniBytes.length & 0xff);
  payload.push(...sniBytes);

  // Extension: Extended Master Secret (0x0017)
  payload.push(0x00, 0x17, 0x00, 0x00);

  // Extension: Supported Groups (0x000a)
  payload.push(0x00, 0x0a, 0x00, 0x08, 0x00, 0x06, 0x00, 0x1d, 0x00, 0x17, 0x00, 0x18);

  // Extension: EC Point Formats (0x000b)
  payload.push(0x00, 0x0b, 0x00, 0x02, 0x01, 0x00);

  // Extension: Supported Versions (0x002b)
  payload.push(0x00, 0x2b, 0x00, 0x03, 0x02, 0x03, 0x04);

  // Extension: RFC 7685 Padding (0x0015)
  payload.push(0x00, 0x15);
  payload.push((padLen >> 8) & 0xff, padLen & 0xff);
  for (let i = 0; i < padLen; i++) {
    payload.push(0x00);
  }

  // Update extensions length
  const extensionsTotalLen = payload.length - extensionsStart;
  payload[extLenPos] = (extensionsTotalLen >> 8) & 0xff;
  payload[extLenPos + 1] = extensionsTotalLen & 0xff;

  // Update Handshake Length
  const handshakeLen = payload.length - (handshakeStart + 4);
  payload[handshakeStart + 1] = (handshakeLen >> 16) & 0xff;
  payload[handshakeStart + 2] = (handshakeLen >> 8) & 0xff;
  payload[handshakeStart + 3] = handshakeLen & 0xff;

  // Update Record Length
  const recordLen = payload.length - 5;
  payload[3] = (recordLen >> 8) & 0xff;
  payload[4] = recordLen & 0xff;

  return new Uint8Array(payload);
}
