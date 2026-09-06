/**
 * TLS Session Ticket Obfuscator, Active Probing Deflector, and ECH Config API.
 *
 * Ported and unified from `psiphon-tls-master`.
 * Provides standard TLS ticket size normalization to defeat fingerprinting,
 * active probing deflection routing, and Encrypted Client Hello (ECH) Draft-18 parsing.
 */

export const CANONICAL_PADDED_TICKET_SIZES: number[] = [160, 176, 192, 208, 218, 224, 240, 255];

/**
 * Normalizes TLS session ticket size to standard server distributions.
 */
export function padSessionTicket(ticket: Uint8Array): Uint8Array {
  const currLen = ticket.length;
  let targetSize = 0;
  for (const s of CANONICAL_PADDED_TICKET_SIZES) {
    if (s >= currLen) {
      targetSize = s;
      break;
    }
  }
  if (targetSize === 0) {
    targetSize = (currLen + 15) & ~15;
  }

  const out = new Uint8Array(targetSize);
  out.set(ticket, 0);
  return out;
}

/**
 * Strips zero-padding from an obfuscated session ticket.
 */
export function unpadSessionTicket(padded: Uint8Array): Uint8Array {
  let end = padded.length;
  while (end > 0 && padded[end - 1] === 0x00) {
    end--;
  }
  return padded.subarray(0, end);
}

export interface ObfuscatedClientSessionState {
  ticket: Uint8Array;
  vers: number;
  cipherSuite: number;
  masterSecret: Uint8Array;
  createdAt: number;
  ageAdd: number;
  useBy: number;
}

/**
 * Serializes obfuscated session state into a byte buffer.
 */
export function serializeObfuscatedSessionState(state: ObfuscatedClientSessionState): Uint8Array {
  const totalLen = 28 + state.masterSecret.length + state.ticket.length;
  const out = new Uint8Array(totalLen);
  const view = new DataView(out.buffer);

  view.setUint16(0, state.vers, false);
  view.setUint16(2, state.cipherSuite, false);
  view.setBigUint64(4, BigInt(state.createdAt), false);
  view.setUint32(12, state.ageAdd, false);
  view.setBigUint64(16, BigInt(state.useBy), false);

  view.setUint16(24, state.masterSecret.length, false);
  out.set(state.masterSecret, 26);

  const ticketOffset = 26 + state.masterSecret.length;
  view.setUint16(ticketOffset, state.ticket.length, false);
  out.set(state.ticket, ticketOffset + 2);

  return out;
}

/**
 * Deserializes obfuscated session state from binary bytes.
 */
export function deserializeObfuscatedSessionState(data: Uint8Array): ObfuscatedClientSessionState {
  if (data.length < 28) {
    throw new Error(`Buffer too short for session state: ${data.length} < 28`);
  }
  const view = new DataView(data.buffer, data.byteOffset, data.byteLength);

  const vers = view.getUint16(0, false);
  const cipherSuite = view.getUint16(2, false);
  const createdAt = Number(view.getBigUint64(4, false));
  const ageAdd = view.getUint32(12, false);
  const useBy = Number(view.getBigUint64(16, false));

  const secretLen = view.getUint16(24, false);
  let offset = 26;
  if (data.length < offset + secretLen + 2) {
    throw new Error('Buffer truncated at master secret');
  }
  const masterSecret = data.subarray(offset, offset + secretLen);
  offset += secretLen;

  const ticketLen = view.getUint16(offset, false);
  offset += 2;
  if (data.length < offset + ticketLen) {
    throw new Error('Buffer truncated at ticket');
  }
  const ticket = data.subarray(offset, offset + ticketLen);

  return {
    ticket,
    vers,
    cipherSuite,
    masterSecret,
    createdAt,
    ageAdd,
    useBy,
  };
}

export interface TlsPassthroughConfig {
  passthroughAddress?: string;
  authorizedTokens: string[];
}

/**
 * Evaluates whether an incoming connection should be deflected to the fallback server.
 */
export function shouldDeflectTls(config: TlsPassthroughConfig, token?: string): boolean {
  if (!config.passthroughAddress) {
    return false;
  }
  if (!token) {
    return true;
  }
  return !config.authorizedTokens.includes(token);
}

export interface EchCipher {
  kdfId: number;
  aeadId: number;
}

export interface EchConfig {
  version: number;
  configId: number;
  kemId: number;
  publicKey: Uint8Array;
  cipherSuites: EchCipher[];
  maxNameLength: number;
  publicName: string;
}

/**
 * Parses draft-ietf-tls-esni-18 ECHConfigList binary format.
 */
export function parseEchConfigList(data: Uint8Array): EchConfig[] {
  if (data.length < 2) {
    throw new Error('ECHConfigList too short');
  }
  const view = new DataView(data.buffer, data.byteOffset, data.byteLength);
  const listLen = view.getUint16(0, false);
  if (data.length !== 2 + listLen) {
    throw new Error('Malformed ECHConfigList length prefix');
  }

  let offset = 2;
  const configs: EchConfig[] = [];

  while (offset < data.length) {
    if (data.length < offset + 4) {
      throw new Error('Malformed ECHConfig header');
    }

    const vers = view.getUint16(offset, false);
    const cfgLen = view.getUint16(offset + 2, false);
    offset += 4;

    if (data.length < offset + cfgLen) {
      throw new Error('Truncated ECHConfig body');
    }

    const entry = data.subarray(offset, offset + cfgLen);
    const entryView = new DataView(entry.buffer, entry.byteOffset, entry.byteLength);
    offset += cfgLen;

    if (entry.length < 5) {
      throw new Error('ECHConfig entry too short');
    }

    const configId = entry[0]!;
    const kemId = entryView.getUint16(1, false);
    const pkLen = entryView.getUint16(3, false);
    let cOffset = 5;

    if (entry.length < cOffset + pkLen + 2) {
      throw new Error('Truncated ECH public key');
    }
    const publicKey = entry.subarray(cOffset, cOffset + pkLen);
    cOffset += pkLen;

    const ciphersLen = entryView.getUint16(cOffset, false);
    cOffset += 2;

    if (entry.length < cOffset + ciphersLen + 2) {
      throw new Error('Truncated ECH ciphers');
    }

    const cipherSuites: EchCipher[] = [];
    const cEnd = cOffset + ciphersLen;
    while (cOffset + 4 <= cEnd) {
      const kdfId = entryView.getUint16(cOffset, false);
      const aeadId = entryView.getUint16(cOffset + 2, false);
      cipherSuites.push({ kdfId, aeadId });
      cOffset += 4;
    }
    cOffset = cEnd;

    const maxNameLength = entry[cOffset]!;
    cOffset++;

    if (entry.length < cOffset + 1) {
      throw new Error('Missing public name length');
    }
    const nameLen = entry[cOffset]!;
    cOffset++;

    if (entry.length < cOffset + nameLen) {
      throw new Error('Truncated public name');
    }
    const decoder = new TextDecoder();
    const publicName = decoder.decode(entry.subarray(cOffset, cOffset + nameLen));

    configs.push({
      version: vers,
      configId,
      kemId,
      publicKey,
      cipherSuites,
      maxNameLength,
      publicName,
    });
  }

  return configs;
}
