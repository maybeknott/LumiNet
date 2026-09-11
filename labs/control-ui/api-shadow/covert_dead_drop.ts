/**
 * Covert Dead-Drop Binary Framing & AEAD Protocol API
 * Originates from Skirk-main and adapted for LumiNet unified network plane.
 */

export const ENVELOPE_MAGIC = 'SKB1';
export const ENVELOPE_VER = 1;
export const HEADER_LEN = 39;
export const KEY_LEN = 32;

export const DIRECTION_UP = 1;
export const DIRECTION_DOWN = 2;
export const FLAG_DATA = 0;
export const FLAG_FINAL = 1;

export interface BlobEnvelope {
  sessionId: Uint8Array;
  direction: number;
  sequence: bigint;
  flags: number;
  plaintextLen: number;
  ciphertext: Uint8Array;
}

export type CoalesceTier = 'Interactive' | 'Medium' | 'Bulk' | 'ForcedBulk';

export const INTERACTIVE_THRESHOLD = 8 * 1024;
export const BULK_THRESHOLD = 64 * 1024;
export const FORCED_BULK_THRESHOLD = 256 * 1024;

/**
 * Computes 12-byte nonce: sid[0..4] (4 bytes) + direction (1 byte) + sequence (7 bytes big-endian)
 */
export function computeNonce(
  sid: Uint8Array,
  direction: number,
  sequence: bigint
): Uint8Array {
  const out = new Uint8Array(12);
  out.set(sid.subarray(0, 4), 0);
  out[4] = direction & 0xff;
  for (let i = 0; i < 7; i++) {
    out[11 - i] = Number((sequence >> BigInt(8 * i)) & BigInt(0xff));
  }
  return out;
}

/**
 * Evaluates buffering tier based on accumulated payload bytes.
 */
export function evaluateTier(bufferedBytes: number): CoalesceTier {
  if (bufferedBytes < INTERACTIVE_THRESHOLD) {
    return 'Interactive';
  }
  if (bufferedBytes < BULK_THRESHOLD) {
    return 'Medium';
  }
  if (bufferedBytes < FORCED_BULK_THRESHOLD) {
    return 'Bulk';
  }
  return 'ForcedBulk';
}

/**
 * Checks whether buffered data has aged past the tier's threshold or reached forced bulk size.
 */
export function shouldFlush(bufferedBytes: number, ageMs: number): boolean {
  if (bufferedBytes === 0) return false;
  if (bufferedBytes >= FORCED_BULK_THRESHOLD) return true;

  const maxAgeMs = {
    Interactive: 15,
    Medium: 75,
    Bulk: 250,
    ForcedBulk: 1000,
  }[evaluateTier(bufferedBytes)];

  return ageMs >= maxAgeMs;
}
