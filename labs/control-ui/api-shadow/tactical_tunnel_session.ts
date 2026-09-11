/**
 * Tactical Tunnel Session & Obfuscator API.
 *
 * Provides control UI interfaces and protocol framing utilities for tactical
 * multi-protocol tunneling, preamble negotiation, dynamic tactics resolution,
 * and authenticated client-to-client server exchange.
 *
 * Conforms to strict architectural isolation rules: zero vendor prefixes.
 */

export const OBFUSCATE_SEED_LENGTH = 16;
export const OBFUSCATE_KEY_LENGTH = 16;
export const OBFUSCATE_HASH_ITERATIONS = 6000;
export const OBFUSCATE_MAX_PADDING = 8192;
export const OBFUSCATE_MAGIC_VALUE = 0x0bf5ca7e;
export const PREAMBLE_HEADER_LENGTH = OBFUSCATE_SEED_LENGTH + 8;

export interface TacticalSessionConfig {
  keyword: string;
  seedHex: string;
  paddingLength: number;
  targetEndpoint: string;
  fallbackProtocols: string[];
}

export interface TacticalTunnelStats {
  tunnelId: string;
  activeProtocol:
    | 'FRONTED_HTTP'
    | 'FRONTED_MEK'
    | 'UNFRONTED_HTTP'
    | 'OSSH_TUNNEL'
    | 'SHADOWSOCKS'
    | 'TLS_TUNNEL';
  connected: boolean;
  handshakeLatencyMs: number;
  hotSwapsCount: number;
  bytesReceived: number;
  bytesSent: number;
  establishedAt: number;
  currentTag: string;
}

export interface TacticalProfileDto {
  ttlSeconds: number;
  parameters: Record<string, string>;
  tag: string;
}

export interface TacticalFilterDto {
  regions: string[];
  asns: number[];
  maxLatencyMs?: number;
  profile: TacticalProfileDto;
}

export interface ServerExchangePayloadDto {
  serverId: string;
  endpoints: string[];
  capabilities: string[];
  signature: string;
  dialParameters: Record<string, string>;
  timestamp: number;
}

/**
 * Standard RC4 stream cipher state for tactical framing in TypeScript.
 */
export class TacticalStreamCipher {
  private s = new Uint8Array(256);
  private i = 0;
  private j = 0;

  constructor(key: Uint8Array) {
    for (let k = 0; k < 256; k++) {
      this.s[k] = k;
    }
    let j = 0;
    const keyLen = key.length === 0 ? 1 : key.length;
    for (let i = 0; i < 256; i++) {
      const keyByte = key.length === 0 ? 0 : key[i % keyLen];
      j = (j + this.s[i]! + keyByte!) & 0xff;
      const tmp = this.s[i];
      this.s[i] = this.s[j]!;
      this.s[j] = tmp!;
    }
  }

  applyKeyStream(buf: Uint8Array, offset = 0, length = buf.length): void {
    for (let idx = offset; idx < offset + length; idx++) {
      this.i = (this.i + 1) & 0xff;
      this.j = (this.j + this.s[this.i]!) & 0xff;
      const tmp = this.s[this.i];
      this.s[this.i] = this.s[this.j]!;
      this.s[this.j] = tmp!;
      const k = this.s[(this.s[this.i]! + this.s[this.j]!) & 0xff]!;
      buf[idx]! ^= k;
    }
  }
}

/**
 * Validates decrypted preamble magic and padding length.
 */
export function validatePreambleHeader(header: Uint8Array): {
  magic: number;
  paddingLength: number;
  valid: boolean;
} {
  if (header.length < 8) {
    return { magic: 0, paddingLength: 0, valid: false };
  }
  const view = new DataView(header.buffer, header.byteOffset, header.byteLength);
  const magic = view.getUint32(0, false);
  const paddingLength = view.getUint32(4, false);
  const valid = magic === OBFUSCATE_MAGIC_VALUE && paddingLength <= OBFUSCATE_MAX_PADDING;
  return { magic, paddingLength, valid };
}

/**
 * Checks if a given network context satisfies a tactical filter.
 */
export function matchesTacticalFilter(
  filter: TacticalFilterDto,
  region: string,
  asn: number,
  latencyMs: number,
): boolean {
  if (filter.regions.length > 0) {
    const rLower = region.toLowerCase();
    if (!filter.regions.some((r) => r.toLowerCase() === rLower)) {
      return false;
    }
  }
  if (filter.asns.length > 0 && !filter.asns.includes(asn)) {
    return false;
  }
  if (filter.maxLatencyMs !== undefined && latencyMs > filter.maxLatencyMs) {
    return false;
  }
  return true;
}

/**
 * Resolves the active tactical profile by merging matching filter overrides over baseline defaults.
 */
export function resolveTacticalProfile(
  defaultProfile: TacticalProfileDto,
  filters: TacticalFilterDto[],
  region: string,
  asn: number,
  latencyMs: number,
): TacticalProfileDto {
  const mergedParams: Record<string, string> = { ...defaultProfile.parameters };
  let appliedTtl = defaultProfile.ttlSeconds;

  for (const filter of filters) {
    if (matchesTacticalFilter(filter, region, asn, latencyMs)) {
      Object.assign(mergedParams, filter.profile.parameters);
      appliedTtl = filter.profile.ttlSeconds;
    }
  }

  const sortedKeys = Object.keys(mergedParams).sort();
  const tagStr = sortedKeys.map((k) => `${k}=${mergedParams[k]};`).join('');

  return {
    ttlSeconds: appliedTtl,
    parameters: mergedParams,
    tag: `tactical-tag-${tagStr.length}`,
  };
}

/**
 * Client API for interacting with the tactical tunnel session controller.
 */
export class TacticalTunnelClient {
  private baseUrl: string;

  constructor(baseUrl = '/api/v1/tunnel/tactical') {
    this.baseUrl = baseUrl;
  }

  async getSessionStatus(): Promise<TacticalTunnelStats> {
    const res = await fetch(`${this.baseUrl}/status`);
    if (!res.ok) {
      throw new Error(`Failed to fetch tactical session status: ${res.statusText}`);
    }
    return res.json();
  }

  async getTacticsProfile(): Promise<TacticalProfileDto> {
    const res = await fetch(`${this.baseUrl}/tactics`);
    if (!res.ok) {
      throw new Error(`Failed to fetch tactics profile: ${res.statusText}`);
    }
    return res.json();
  }

  async triggerHotSwap(): Promise<{ success: boolean; newChannelId: string }> {
    const res = await fetch(`${this.baseUrl}/hotswap`, { method: 'POST' });
    if (!res.ok) {
      throw new Error(`Failed to trigger channel hot-swap: ${res.statusText}`);
    }
    return res.json();
  }

  async exportExchangePayload(): Promise<{ payloadHex: string }> {
    const res = await fetch(`${this.baseUrl}/exchange/export`, {
      method: 'POST',
    });
    if (!res.ok) {
      throw new Error(`Failed to export server exchange payload: ${res.statusText}`);
    }
    return res.json();
  }

  async importExchangePayload(payloadHex: string): Promise<{ success: boolean; serverId: string }> {
    const res = await fetch(`${this.baseUrl}/exchange/import`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ payloadHex }),
    });
    if (!res.ok) {
      throw new Error(`Failed to import server exchange payload: ${res.statusText}`);
    }
    return res.json();
  }
}
