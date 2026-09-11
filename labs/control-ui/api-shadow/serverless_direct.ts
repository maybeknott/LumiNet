/**
 * Serverless Direct Shaper & Zero-VPS Evasion API
 * Originates from Serverless-for-Iran-main and adapted for LumiNet unified network plane.
 */

export type ServerlessProfile = 'LowDelay' | 'HighDelay';

export interface ServerlessShaperConfig {
  profile: ServerlessProfile;
  tls_record_split: number;
  sni_split_offset: number;
  max_split_tls: number;
  max_split_tcp: number;
  happy_eyeballs_ipv6_first: boolean;
  udp_noise_enabled: boolean;
  udp_noise_min_len: number;
  udp_noise_max_len: number;
  udp_noise_reset_interval: number;
}

export const DEFAULT_SERVERLESS_SHAPER_CONFIG: ServerlessShaperConfig = {
  profile: 'LowDelay',
  tls_record_split: 5,
  sni_split_offset: 43,
  max_split_tls: 522,
  max_split_tcp: 419,
  happy_eyeballs_ipv6_first: true,
  udp_noise_enabled: true,
  udp_noise_min_len: 1200,
  udp_noise_max_len: 1230,
  udp_noise_reset_interval: 28,
};

export interface ShaperFragment {
  payload: Uint8Array;
  delay_ms: number;
}

/**
 * Checks whether an IP matches Iranian national censorship redirection landing sinks:
 * - IPv4: 10.10.34.0/24
 * - IPv6: 2001:4188:2:600::/64
 */
export function isCensorshipSink(ip: string): boolean {
  if (ip.startsWith('10.10.34.')) {
    return true;
  }
  const lower = ip.toLowerCase();
  if (lower.startsWith('2001:4188:2:600:') || lower.startsWith('2001:4188:0002:0600:')) {
    return true;
  }
  return false;
}

/**
 * Computes fragment delay in ms for slice index based on profile.
 */
export function calculateDelay(sliceIdx: number, profile: ServerlessProfile): number {
  if (profile === 'LowDelay') {
    return 1;
  }
  if (sliceIdx > 0 && sliceIdx % 10 === 0) {
    return 400;
  }
  return 1;
}

/**
 * Shapes a TLS ClientHello packet across record boundaries, SNI offsets,
 * and 1-byte micro-fragments with profile-directed pacing.
 */
export function shapeClientHello(
  payload: Uint8Array,
  config: ServerlessShaperConfig = DEFAULT_SERVERLESS_SHAPER_CONFIG
): ShaperFragment[] {
  if (payload.length === 0) {
    return [];
  }

  const recordSplit = config.tls_record_split > 0 ? config.tls_record_split : 5;
  if (payload.length <= recordSplit) {
    return [{ payload: new Uint8Array(payload), delay_ms: 0 }];
  }

  const fragments: ShaperFragment[] = [];

  // 1. Record header (0..recordSplit)
  fragments.push({
    payload: payload.slice(0, recordSplit),
    delay_ms: 0,
  });

  let currOffset = recordSplit;

  // 2. Prefix up to SNI boundary
  const sniBoundary = Math.min(config.sni_split_offset, payload.length);
  if (sniBoundary > currOffset) {
    fragments.push({
      payload: payload.slice(currOffset, sniBoundary),
      delay_ms: calculateDelay(0, config.profile),
    });
    currOffset = sniBoundary;
  }

  // 3. Remainder split into 1-byte chunks up to max_split_tls
  let sliceIdx = 1;
  const maxSplit = config.max_split_tls > 0 ? config.max_split_tls : 522;

  while (currOffset < payload.length && currOffset < maxSplit) {
    const chunkLen = Math.min(1, payload.length - currOffset);
    const delay = calculateDelay(sliceIdx, config.profile);
    fragments.push({
      payload: payload.slice(currOffset, currOffset + chunkLen),
      delay_ms: delay,
    });
    currOffset += chunkLen;
    sliceIdx++;
  }

  // 4. Any leftover beyond maxSplit as final fragment
  if (currOffset < payload.length) {
    fragments.push({
      payload: payload.slice(currOffset),
      delay_ms: calculateDelay(sliceIdx, config.profile),
    });
  }

  return fragments;
}
