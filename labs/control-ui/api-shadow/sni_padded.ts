/**
 * RFC 7685 Constant-Size (517-byte) Padded TLS ClientHello Generator API.
 *
 * Ported and elevated from `sni-spoofing-rust-main`.
 * Generates deterministic 517-byte ClientHello packets to defeat DPI length profiling.
 *
 * Conforms to strict architectural isolation rules: zero vendor prefixes.
 */

export const CLIENT_HELLO_CONSTANT_SIZE = 517;
export const EXTENSION_SERVER_NAME = 0x0000;
export const EXTENSION_PADDING = 0x0015; // RFC 7685
export const MAX_SNI_LENGTH_FOR_PADDING = 215;

export interface SniPaddingConfig {
  targetSni: string;
  constantSize: number;
  enableRfc7685Padding: boolean;
}

export interface SniPaddingStatus {
  enabled: boolean;
  activeConstantSize: number;
  packetsSent: number;
  lastGeneratedSni: string;
}

/**
 * Validates whether a TLS ClientHello packet matches the required constant size.
 */
export function validateClientHelloLength(packet: Uint8Array): {
  valid: boolean;
  length: number;
  recordVersion: number;
  handshakeType: number;
} {
  if (packet.length < 6) {
    return { valid: false, length: packet.length, recordVersion: 0, handshakeType: 0 };
  }
  const view = new DataView(packet.buffer, packet.byteOffset, packet.byteLength);
  const recordType = view.getUint8(0);
  const recordVersion = view.getUint16(1, false);
  const handshakeType = view.getUint8(5);
  const valid = recordType === 0x16 && handshakeType === 0x01 && packet.length === CLIENT_HELLO_CONSTANT_SIZE;
  return { valid, length: packet.length, recordVersion, handshakeType };
}

/**
 * Client API for managing constant-size SNI padding evasion.
 */
export class SniPaddingClient {
  private baseUrl: string;

  constructor(baseUrl = '/api/v1/evasion/sni-padding') {
    this.baseUrl = baseUrl;
  }

  async getStatus(): Promise<SniPaddingStatus> {
    const res = await fetch(`${this.baseUrl}/status`);
    if (!res.ok) {
      throw new Error(`Failed to fetch SNI padding status: ${res.statusText}`);
    }
    return res.json();
  }

  async configure(config: SniPaddingConfig): Promise<{ success: boolean }> {
    const res = await fetch(`${this.baseUrl}/configure`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify(config),
    });
    if (!res.ok) {
      throw new Error(`Failed to configure SNI padding: ${res.statusText}`);
    }
    return res.json();
  }
}
