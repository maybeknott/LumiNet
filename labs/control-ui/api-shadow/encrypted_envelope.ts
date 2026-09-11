// SPDX-License-Identifier: MIT
//
// EncryptedPayloadEnvelope Codec.
// Ported and unified from donor EncryptedPayloadEnvelope.kt.

export interface EncryptedPayloadEnvelope {
  version: number;
  algorithm: string;
  encoding: string;
  iv: string;
  ciphertext: string;
}

export const SUPPORTED_VERSION = 1;
export const SUPPORTED_ALGO = 'AES-GCM';
export const SUPPORTED_ENCODING = 'base64url';

export function validateEnvelopeStructure(raw: unknown): EncryptedPayloadEnvelope {
  if (typeof raw !== 'object' || raw === null) {
    throw new Error('Invalid envelope: expected JSON object');
  }
  const obj = raw as Record<string, unknown>;
  if (obj.version !== SUPPORTED_VERSION) {
    throw new Error(`Unsupported envelope version: expected ${SUPPORTED_VERSION}, got ${obj.version}`);
  }
  if (obj.algorithm !== SUPPORTED_ALGO) {
    throw new Error(`Unsupported envelope algorithm: expected ${SUPPORTED_ALGO}, got ${obj.algorithm}`);
  }
  if (obj.encoding !== SUPPORTED_ENCODING) {
    throw new Error(`Unsupported envelope encoding: expected ${SUPPORTED_ENCODING}, got ${obj.encoding}`);
  }
  if (typeof obj.iv !== 'string' || obj.iv.length === 0) {
    throw new Error('Envelope missing required iv string');
  }
  if (typeof obj.ciphertext !== 'string' || obj.ciphertext.length === 0) {
    throw new Error('Envelope missing required ciphertext string');
  }

  return {
    version: obj.version,
    algorithm: obj.algorithm,
    encoding: obj.encoding,
    iv: obj.iv,
    ciphertext: obj.ciphertext,
  };
}

function toBase64Url(bytes: Uint8Array): string {
  let binary = '';
  for (let i = 0; i < bytes.length; i++) {
    binary += String.fromCharCode(bytes[i]!);
  }
  return btoa(binary).replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/, '');
}

function fromBase64Url(str: string): Uint8Array {
  let base64 = str.replace(/-/g, '+').replace(/_/g, '/');
  while (base64.length % 4) {
    base64 += '=';
  }
  const binary = atob(base64);
  const bytes = new Uint8Array(binary.length);
  for (let i = 0; i < binary.length; i++) {
    bytes[i] = binary.charCodeAt(i);
  }
  return bytes;
}

/**
 * Derives an AES-GCM CryptoKey from a passphrase using SHA-256.
 */
export async function deriveKey(passphrase: string): Promise<CryptoKey> {
  const trimmed = passphrase.trim();
  if (!trimmed) {
    throw new Error('Passphrase cannot be blank');
  }
  const enc = new TextEncoder();
  const passBytes = enc.encode(trimmed);
  const hash = await crypto.subtle.digest('SHA-256', passBytes);
  return crypto.subtle.importKey('raw', hash, { name: 'AES-GCM' }, false, [
    'encrypt',
    'decrypt',
  ]);
}

/**
 * Encrypts arbitrary bytes into an EncryptedPayloadEnvelope.
 */
export async function encryptPayload(
  plaintext: Uint8Array,
  passphrase: string,
): Promise<EncryptedPayloadEnvelope> {
  const key = await deriveKey(passphrase);
  const iv = new Uint8Array(12);
  crypto.getRandomValues(iv);

  const ciphertextBuf = await crypto.subtle.encrypt(
    { name: 'AES-GCM', iv, tagLength: 128 },
    key,
    plaintext as Uint8Array<ArrayBuffer>,
  );

  return {
    version: SUPPORTED_VERSION,
    algorithm: SUPPORTED_ALGO,
    encoding: SUPPORTED_ENCODING,
    iv: toBase64Url(iv),
    ciphertext: toBase64Url(new Uint8Array(ciphertextBuf)),
  };
}

/**
 * Decrypts an EncryptedPayloadEnvelope into raw bytes.
 */
export async function decryptPayload(
  envelope: EncryptedPayloadEnvelope,
  passphrase: string,
): Promise<Uint8Array> {
  validateEnvelopeStructure(envelope);
  const key = await deriveKey(passphrase);
  const iv = fromBase64Url(envelope.iv);
  const ciphertext = fromBase64Url(envelope.ciphertext);

  const decryptedBuf = await crypto.subtle.decrypt(
    { name: 'AES-GCM', iv: iv as Uint8Array<ArrayBuffer>, tagLength: 128 },
    key,
    ciphertext as Uint8Array<ArrayBuffer>,
  );

  return new Uint8Array(decryptedBuf);
}

export function parsePlaintextIps(text: string): string[] {
  const seen = new Set<string>();
  const result: string[] = [];

  const tokens = text.trim().split(/\s+/);
  for (const token of tokens) {
    const trimmed = token.trim();
    if (isValidIpv4(trimmed) && !seen.has(trimmed)) {
      seen.add(trimmed);
      result.push(trimmed);
    }
  }
  return result;
}

function isValidIpv4(value: string): boolean {
  const octets = value.split('.');
  if (octets.length !== 4) return false;
  return octets.every((octet) => {
    const n = Number(octet);
    return !Number.isNaN(n) && n >= 0 && n <= 255 && octet === String(n);
  });
}

/**
 * Encrypts a list of IP addresses into an envelope string.
 */
export async function encryptIpList(ips: string[], passphrase: string): Promise<string> {
  const text = ips.join('\n');
  const enc = new TextEncoder();
  const envelope = await encryptPayload(enc.encode(text), passphrase);
  return JSON.stringify(envelope);
}

/**
 * Decrypts an envelope string into a list of parsed valid IPv4 addresses.
 */
export async function decryptIpList(envelopeJson: string, passphrase: string): Promise<string[]> {
  const parsed = JSON.parse(envelopeJson);
  const envelope = validateEnvelopeStructure(parsed);
  const decryptedBytes = await decryptPayload(envelope, passphrase);
  const dec = new TextDecoder();
  const text = dec.decode(decryptedBytes);
  const ips = parsePlaintextIps(text);
  if (ips.length === 0) {
    throw new Error('Decrypted IP list contained no usable IPv4 addresses');
  }
  return ips;
}
