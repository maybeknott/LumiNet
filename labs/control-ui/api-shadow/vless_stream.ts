/**
 * VLESS protocol command types.
 */
export type VlessCommand = 'tcp' | 'udp' | 'mux';

/**
 * Address type in VLESS protocol framing.
 */
export type VlessAddressType = 'ipv4' | 'domain' | 'ipv6';

/**
 * VLESS client endpoint configuration.
 */
export interface VlessConfig {
  address: string;
  port: number;
  uuid: string;
  transport?: 'tcp' | 'ws' | 'grpc';
  tls?: boolean;
  sni?: string;
  flow?: string;
  path?: string;
}

/**
 * VLESS request descriptor.
 */
export interface VlessRequestHeader {
  version: number;
  uuid: string; // 32-hex or 36-char formatted UUID
  command: VlessCommand;
  targetHost: string;
  targetPort: number;
  addons?: Uint8Array;
}

/**
 * VLESS session telemetry and status.
 */
export interface VlessSessionMetrics {
  connected: boolean;
  targetHost: string;
  targetPort: number;
  transport: string;
  bytesUploaded: number;
  bytesDownloaded: number;
  rttMs: number;
}

/**
 * Encodes a UUID string (hyphenated or raw hex) into 16 bytes.
 */
export function parseUuidToBytes(uuidStr: string): Uint8Array {
  const clean = uuidStr.replace(/-/g, '');
  if (clean.length !== 32) {
    throw new Error(`Invalid UUID length: ${clean.length}`);
  }
  const bytes = new Uint8Array(16);
  for (let i = 0; i < 16; i++) {
    bytes[i] = parseInt(clean.slice(i * 2, i * 2 + 2), 16);
  }
  return bytes;
}

/**
 * Builds the binary VLESS handshake request header bytes.
 */
export function buildVlessRequestHeader(req: VlessRequestHeader): Uint8Array {
  const uuidBytes = parseUuidToBytes(req.uuid);
  const addons = req.addons || new Uint8Array(0);

  // Determine address type
  const isIpv4 = /^(\d{1,3}\.){3}\d{1,3}$/.test(req.targetHost);
  let addrBytes: Uint8Array;

  if (isIpv4) {
    const parts = req.targetHost.split('.').map((p) => parseInt(p, 10));
    addrBytes = new Uint8Array([0x01, ...parts]);
  } else {
    // Domain
    const enc = new TextEncoder().encode(req.targetHost);
    addrBytes = new Uint8Array(2 + enc.length);
    addrBytes[0] = 0x02;
    addrBytes[1] = enc.length;
    addrBytes.set(enc, 2);
  }

  const cmdByte = req.command === 'tcp' ? 1 : req.command === 'udp' ? 2 : 3;
  const totalLen = 1 + 16 + 1 + addons.length + 1 + 2 + addrBytes.length;
  const out = new Uint8Array(totalLen);

  let offset = 0;
  out[offset++] = req.version; // Version
  out.set(uuidBytes, offset); // UUID (16 bytes)
  offset += 16;

  out[offset++] = addons.length; // Addons length
  if (addons.length > 0) {
    out.set(addons, offset);
    offset += addons.length;
  }

  out[offset++] = cmdByte; // Command

  // Port big-endian
  out[offset++] = (req.targetPort >> 8) & 0xff;
  out[offset++] = req.targetPort & 0xff;

  // Address
  out.set(addrBytes, offset);

  return out;
}

/**
 * Parses a VLESS response header (version + addons length + addons).
 */
export function parseVlessResponseHeader(data: Uint8Array): {
  version: number;
  addons: Uint8Array;
  bytesConsumed: number;
} {
  if (data.length < 2) {
    throw new Error('VLESS response header too short');
  }
  const version = data[0]!;
  const addonsLen = data[1]!;
  if (data.length < 2 + addonsLen) {
    throw new Error('VLESS response addons buffer truncated');
  }
  const addons = data.slice(2, 2 + addonsLen);
  return {
    version,
    addons,
    bytesConsumed: 2 + addonsLen,
  };
}
