/**
 * Cloudflare WARP Endpoint Scanner & WireGuard Handshake Prober API.
 *
 * Ported and unified from `ipscanner-main` and `warp-plus-master`.
 * Provides 54-port candidate pool generation, WireGuard Noise_IK initiation message crafting,
 * response validation, and multi-attempt loss/jitter/RTT ranking.
 */

export const WARP_PORTS: number[] = [
  500, 854, 859, 864, 878, 880, 890, 891, 894, 903, 908, 928, 934, 939, 942, 943, 945, 946, 955,
  968, 987, 988, 1002, 1010, 1014, 1018, 1070, 1074, 1180, 1387, 1701, 1843, 2371, 2408, 2506, 3138,
  3476, 3581, 3854, 4177, 4198, 4233, 4500, 5279, 5956, 7103, 7152, 7156, 7281, 7559, 8319, 8742,
  8854, 8886,
];

export const WARP_IPV4_PREFIXES: string[] = [
  '162.159.192',
  '162.159.193',
  '162.159.195',
  '188.114.96',
  '188.114.97',
  '188.114.98',
  '188.114.99',
];

export const WARP_IPV6_PREFIXES: string[] = ['2606:4700:d0::', '2606:4700:d1::'];

export const DEFAULT_WARP_PEER_PUBLIC_KEY = 'bmXOC+F1FxEMF9dyiK2H5/1SUtzH0JuVo51h2wPfgyo=';

export const INITIATION_PACKET_LEN = 148;
export const RESPONSE_PACKET_LEN = 92;

export interface WarpScanResult {
  endpoint: string;
  rttMs: number;
  jitterMs: number;
  lossPct: number;
  attempts: number;
  successfulAttempts: number;
}

export interface WarpScannerConfig {
  concurrency?: number;
  maxCandidates?: number;
  attemptsPerEndpoint?: number;
  useIpv6?: boolean;
  timeoutMs?: number;
}

/**
 * Selects a random WARP UDP port from the canonical 54-port list.
 */
export function selectRandomWarpPort(): number {
  return WARP_PORTS[Math.floor(Math.random() * WARP_PORTS.length)]!;
}

/**
 * Generates an array of randomized candidate IP:Port endpoints.
 */
export function generateWarpCandidates(count: number, useIpv6: boolean = false): string[] {
  const candidates: string[] = [];
  const prefixes = useIpv6 ? WARP_IPV6_PREFIXES : WARP_IPV4_PREFIXES;

  for (let i = 0; i < count; i++) {
    const prefix = prefixes[Math.floor(Math.random() * prefixes.length)];
    const port = selectRandomWarpPort();
    if (useIpv6) {
      const suffix = Math.floor(Math.random() * 65535).toString(16);
      candidates.push(`[${prefix}${suffix}]:${port}`);
    } else {
      const hostOctet = 1 + Math.floor(Math.random() * 254);
      candidates.push(`${prefix}.${hostOctet}:${port}`);
    }
  }
  return candidates;
}

/**
 * Builds a 148-byte WireGuard Noise_IK Initiation packet for ping probing.
 */
export function buildWarpInitiationPacket(senderIndex: number = 28): Uint8Array {
  const pkt = new Uint8Array(INITIATION_PACKET_LEN);
  const view = new DataView(pkt.buffer);

  // Type 1: Initiation (Little Endian)
  view.setUint32(0, 1, true);
  // Sender Index
  view.setUint32(4, senderIndex, true);

  // Mock uncalibrated ephemeral & static keys
  if (typeof crypto !== 'undefined' && crypto.getRandomValues) {
    const randomSub = new Uint8Array(INITIATION_PACKET_LEN - 8 - 16);
    crypto.getRandomValues(randomSub);
    pkt.set(randomSub, 8);
  } else {
    for (let i = 8; i < 132; i++) {
      pkt[i] = Math.floor(Math.random() * 256);
    }
  }

  // MAC2 (16 bytes) at offset 132 left as zeros
  for (let i = 132; i < 148; i++) {
    pkt[i] = 0;
  }

  return pkt;
}

/**
 * Validates a 92-byte WireGuard Response packet and matches the sender index.
 */
export function validateWarpResponse(
  packet: Uint8Array,
  expectedSenderIndex: number = 28,
): boolean {
  if (packet.length < RESPONSE_PACKET_LEN) {
    return false;
  }
  const view = new DataView(packet.buffer, packet.byteOffset, packet.byteLength);
  const msgType = view.getUint32(0, true);
  if (msgType !== 2) {
    return false;
  }
  const receiverIndex = view.getUint32(8, true);
  return receiverIndex === expectedSenderIndex;
}

/**
 * Ranks endpoints strictly prioritizing:
 * 1. Lowest packet loss percentage
 * 2. Lowest jitter
 * 3. Lowest median RTT
 */
export function rankWarpEndpoints(results: WarpScanResult[]): WarpScanResult[] {
  return [...results].sort((a, b) => {
    if (a.lossPct !== b.lossPct) {
      return a.lossPct - b.lossPct;
    }
    if (a.jitterMs !== b.jitterMs) {
      return a.jitterMs - b.jitterMs;
    }
    return a.rttMs - b.rttMs;
  });
}
