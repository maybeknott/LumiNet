// SPDX-License-Identifier: MIT
//
// ProfileKey — Deterministic Content-Derived Proxy/VPN Profile Fingerprinting.
// Ported and unified from donor ProfileKey.kt (C9.1).
//
// Computes a stable SHA-256 key over canonical routing-relevant parameters
// (protocol, host, port, identity, transport, tls, path, sni), intentionally
// stripping cosmetic labels/aliases so that renamed or re-imported profiles
// can be detected, deduplicated, or updated without duplication.

export interface V2rayProfileInput {
  protocol: string;
  host: string;
  port: number;
  uuid?: string | null | undefined;
  password?: string | null | undefined;
  network?: string | null | undefined;
  tls?: string | null | undefined;
  path?: string | null | undefined;
  sni?: string | null | undefined;
  alias?: string | null | undefined;
}

export interface ProfileKey {
  /** Hex-encoded SHA-256 (lowercase, 64 chars). */
  hash: string;
  /** Short human-readable identifier (first 12 hex chars). */
  shortHash: string;
  /** Source scheme/protocol. */
  protocol: string;
  /** Destination host or IP. */
  host: string;
  /** Destination port. */
  port: number;
  /** User identity (UUID or password) if specified. */
  identity?: string | undefined;
  /** Transport network (tcp, ws, grpc, etc.). */
  transport: string;
  /** Security variant (none, tls, reality). */
  security: string;
}

export const MatchDecision = {
  Match: 'MATCH',
  Mismatch: 'MISMATCH',
} as const;
export type MatchDecision = (typeof MatchDecision)[keyof typeof MatchDecision];

/**
 * Pure TypeScript synchronous SHA-256 implementation conforming to FIPS 180-4.
 */
function sha256Hex(asciiOrUtf8Str: string): string {
  const utf8: number[] = [];
  for (let i = 0; i < asciiOrUtf8Str.length; i++) {
    let charcode = asciiOrUtf8Str.charCodeAt(i);
    if (charcode < 0x80) utf8.push(charcode);
    else if (charcode < 0x800) {
      utf8.push(0xc0 | (charcode >> 6), 0x80 | (charcode & 0x3f));
    } else if (charcode < 0xd800 || charcode >= 0xe000) {
      utf8.push(0xe0 | (charcode >> 12), 0x80 | ((charcode >> 6) & 0x3f), 0x80 | (charcode & 0x3f));
    } else {
      // Surrogate pair
      i++;
      charcode = 0x10000 + (((charcode & 0x3ff) << 10) | (asciiOrUtf8Str.charCodeAt(i) & 0x3ff));
      utf8.push(
        0xf0 | (charcode >> 18),
        0x80 | ((charcode >> 12) & 0x3f),
        0x80 | ((charcode >> 6) & 0x3f),
        0x80 | (charcode & 0x3f),
      );
    }
  }

  const K = [
    0x428a2f98, 0x71374491, 0xb5c0fbcf, 0xe9b5dba5, 0x3956c25b, 0x59f111f1, 0x923f82a4, 0xab1c5ed5,
    0xd807aa98, 0x12835b01, 0x243185be, 0x550c7dc3, 0x72be5d74, 0x80deb1fe, 0x9bdc06a7, 0xc19bf174,
    0xe49b69c1, 0xefbe4786, 0x0fc19dc6, 0x240ca1cc, 0x2de92c6f, 0x4a7484aa, 0x5cb0a9dc, 0x76f988da,
    0x983e5152, 0xa831c66d, 0xb00327c8, 0xbf597fc7, 0xc6e00bf3, 0xd5a79147, 0x06ca6351, 0x14292967,
    0x27b70a85, 0x2e1b2138, 0x4d2c6dfc, 0x53380d13, 0x650a7354, 0x766a0abb, 0x81c2c92e, 0x92722c85,
    0xa2bfe8a1, 0xa81a664b, 0xc24b8b70, 0xc76c51a3, 0xd192e819, 0xd6990624, 0xf40e3585, 0x106aa070,
    0x19a4c116, 0x1e376c08, 0x2748774c, 0x34b0bcb5, 0x391c0cb3, 0x4ed8aa4a, 0x5b9cca4f, 0x682e6ff3,
    0x748f82ee, 0x78a5636f, 0x84c87814, 0x8cc70208, 0x90befffa, 0xa4506ceb, 0xbef9a3f7, 0xc67178f2,
  ];

  let H0 = 0x6a09e667,
    H1 = 0xbb67ae85,
    H2 = 0x3c6ef372,
    H3 = 0xa54ff53a,
    H4 = 0x510e527f,
    H5 = 0x9b05688c,
    H6 = 0x1f83d9ab,
    H7 = 0x5be0cd19;

  const bitLength = utf8.length * 8;
  utf8.push(0x80);
  while ((utf8.length % 64) !== 56) utf8.push(0);

  // Append 64-bit big endian length
  const hi = Math.floor(bitLength / 0x100000000);
  const lo = bitLength >>> 0;
  utf8.push(
    (hi >>> 24) & 0xff,
    (hi >>> 16) & 0xff,
    (hi >>> 8) & 0xff,
    hi & 0xff,
    (lo >>> 24) & 0xff,
    (lo >>> 16) & 0xff,
    (lo >>> 8) & 0xff,
    lo & 0xff,
  );

  const W = new Int32Array(64);

  const rotr = (x: number, n: number) => (x >>> n) | (x << (32 - n));

  for (let i = 0; i < utf8.length; i += 64) {
    for (let t = 0; t < 16; t++) {
      W[t] =
        ((utf8[i + t * 4]! & 0xff) << 24) |
        ((utf8[i + t * 4 + 1]! & 0xff) << 16) |
        ((utf8[i + t * 4 + 2]! & 0xff) << 8) |
        (utf8[i + t * 4 + 3]! & 0xff);
    }
    for (let t = 16; t < 64; t++) {
      const s0 = rotr(W[t - 15]!, 7) ^ rotr(W[t - 15]!, 18) ^ (W[t - 15]! >>> 3);
      const s1 = rotr(W[t - 2]!, 17) ^ rotr(W[t - 2]!, 19) ^ (W[t - 2]! >>> 10);
      W[t] = (W[t - 16]! + s0 + W[t - 7]! + s1) | 0;
    }

    let a = H0,
      b = H1,
      c = H2,
      d = H3,
      e = H4,
      f = H5,
      g = H6,
      h = H7;

    for (let t = 0; t < 64; t++) {
      const S1 = rotr(e, 6) ^ rotr(e, 11) ^ rotr(e, 25);
      const ch = (e & f) ^ (~e & g);
      const temp1 = (h + S1 + ch + K[t]! + W[t]!) | 0;
      const S0 = rotr(a, 2) ^ rotr(a, 13) ^ rotr(a, 22);
      const maj = (a & b) ^ (a & c) ^ (b & c);
      const temp2 = (S0 + maj) | 0;

      h = g;
      g = f;
      f = e;
      e = (d + temp1) | 0;
      d = c;
      c = b;
      b = a;
      a = (temp1 + temp2) | 0;
    }

    H0 = (H0 + a) | 0;
    H1 = (H1 + b) | 0;
    H2 = (H2 + c) | 0;
    H3 = (H3 + d) | 0;
    H4 = (H4 + e) | 0;
    H5 = (H5 + f) | 0;
    H6 = (H6 + g) | 0;
    H7 = (H7 + h) | 0;
  }

  const toHex = (n: number) => (n >>> 0).toString(16).padStart(8, '0');
  return `${toHex(H0)}${toHex(H1)}${toHex(H2)}${toHex(H3)}${toHex(H4)}${toHex(H5)}${toHex(H6)}${toHex(H7)}`;
}

/**
 * Compute a content-derived ProfileKey for a v2ray profile record.
 * Strips display-only alias/remarks.
 */
export function computeProfileKey(profile: V2rayProfileInput): ProfileKey {
  const protocol = profile.protocol?.trim().toLowerCase() || '';
  const host = profile.host?.trim().toLowerCase() || '';
  const port = profile.port;

  if (!protocol) throw new Error('Profile protocol must not be blank');
  if (!host) throw new Error('Profile host must not be blank');
  if (typeof port !== 'number' || port < 0 || port > 65535) {
    throw new Error(`Profile port out of range: ${port}`);
  }

  const canonical = {
    protocol,
    host,
    port,
    uuid: profile.uuid?.trim().toLowerCase() || null,
    password: profile.password?.trim() || null,
    network: profile.network?.trim().toLowerCase() || 'tcp',
    tls: profile.tls?.trim().toLowerCase() || 'none',
    path: profile.path?.trim() || null,
    sni: profile.sni?.trim().toLowerCase() || null,
  };

  const jsonString = JSON.stringify(canonical);
  const hash = sha256Hex(jsonString);

  return {
    hash,
    shortHash: hash.substring(0, 12),
    protocol: canonical.protocol,
    host: canonical.host,
    port: canonical.port,
    identity: canonical.uuid || canonical.password || undefined,
    transport: canonical.network,
    security: canonical.tls,
  };
}

/**
 * Decide whether incoming matches an existing profile key.
 */
export function matchProfile(existing: ProfileKey, incoming: ProfileKey): MatchDecision {
  if (existing.hash !== incoming.hash) {
    return MatchDecision.Mismatch;
  }
  // Deep safety check on identity fields
  if (
    existing.protocol !== incoming.protocol ||
    existing.host !== incoming.host ||
    existing.port !== incoming.port
  ) {
    return MatchDecision.Mismatch;
  }
  return MatchDecision.Match;
}
