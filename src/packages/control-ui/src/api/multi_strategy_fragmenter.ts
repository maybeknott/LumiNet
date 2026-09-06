/**
 * Multi-Strategy TLS Fragmenter & Carrier Edge Selector
 * Originates from UAC-SNI-Spoofer-Android-main and adapted for LumiNet Control UI.
 */

export type MultiFragmentStrategy =
  | 'FINALMASK_TLS_HELLO'
  | 'FULL5'
  | 'FULL10'
  | 'FULL20'
  | 'SNI_BOUNDARY'
  | 'SNI_SPLIT'
  | 'TLS_RECORD_FRAG'
  | 'TLS_SNI_RECORDS'
  | 'HALF'
  | 'RAW';

export interface FinalMaskSettings {
  packet: string;
  length: number;
  delayMs: number;
  maxSplit: number;
}

export const DEFAULT_FINALMASK_SETTINGS: FinalMaskSettings = {
  packet: 'tlshello',
  length: 5,
  delayMs: 0,
  maxSplit: 2,
};

export interface CarrierEdge {
  address: string;
  port: number;
  role: string;
  finalmaskMaxSplit: number;
}

export const DEFAULT_MCI_EDGES: CarrierEdge[] = [
  { address: '104.18.1.1', port: 443, role: 'primary', finalmaskMaxSplit: 2 },
  {
    address: '104.18.1.1',
    port: 443,
    role: 'irancell',
    finalmaskMaxSplit: 100,
  },
  { address: '172.66.0.1', port: 443, role: 'fallback', finalmaskMaxSplit: 2 },
];

export class CarrierRouteSelector {
  private failedUntil: Map<string, number> = new Map();
  private cooldownMs: number;
  private clockMs: () => number;
  constructor(cooldownMs: number = 12000, clockMs: () => number = () => Date.now()) {
    this.cooldownMs = cooldownMs;
    this.clockMs = clockMs;
  }

  orderedEdges(edges: CarrierEdge[]): CarrierEdge[] {
    const now = this.clockMs();
    const healthy: CarrierEdge[] = [];
    const coolingDown: CarrierEdge[] = [];

    for (const edge of edges) {
      const until = this.failedUntil.get(edge.address) ?? 0;
      if (until > now) {
        coolingDown.push(edge);
      } else {
        healthy.push(edge);
      }
    }

    return [...healthy, ...coolingDown];
  }

  recordFailure(edge: CarrierEdge): void {
    this.failedUntil.set(edge.address, this.clockMs() + this.cooldownMs);
  }

  recordSuccess(edge: CarrierEdge): void {
    this.failedUntil.delete(edge.address);
  }

  isInCooldown(edge: CarrierEdge): boolean {
    return (this.failedUntil.get(edge.address) ?? 0) > this.clockMs();
  }
}

/**
 * Scans a TLS ClientHello packet to locate the byte offset and length of the SNI hostname.
 */
export function locateSni(data: Uint8Array): [number, number] | null {
  if (data.length < 9 || data[0] !== 0x16) return null;

  const recordLen = (data[3]! << 8) | data[4]!;
  const recordEnd = Math.min(data.length, 5 + recordLen);

  let pos = 5;
  if (pos >= recordEnd || data[pos] !== 0x01) return null;

  pos += 4 + 2 + 32; // handshake (4) + version (2) + random (32)
  if (pos >= recordEnd) return null;

  const sessionLen = data[pos]!;
  pos += 1 + sessionLen;
  if (pos + 2 > recordEnd) return null;

  const cipherLen = (data[pos]! << 8) | data[pos + 1]!;
  pos += 2 + cipherLen;
  if (pos + 1 > recordEnd) return null;

  const compLen = data[pos]!;
  pos += 1 + compLen;
  if (pos + 2 > recordEnd) return null;

  const extLen = (data[pos]! << 8) | data[pos + 1]!;
  pos += 2;
  const extEnd = Math.min(recordEnd, pos + extLen);

  while (pos + 4 <= extEnd) {
    const extType = (data[pos]! << 8) | data[pos + 1]!;
    const extDataLen = (data[pos + 2]! << 8) | data[pos + 3]!;
    pos += 4;

    if (extType === 0x0000 && pos + extDataLen <= extEnd) {
      let namePos = pos + 2;
      const namesEnd = pos + extDataLen;
      while (namePos + 3 <= namesEnd) {
        const nameType = data[namePos];
        const nameLen = (data[namePos + 1]! << 8) | data[namePos + 2]!;
        namePos += 3;
        if (nameType === 0 && namePos + nameLen <= namesEnd) {
          return [namePos, nameLen];
        }
        namePos += nameLen;
      }
    }
    pos += extDataLen;
  }

  return null;
}

export function extractSni(data: Uint8Array): string | null {
  const loc = locateSni(data);
  if (!loc) return null;
  const [offset, len] = loc;
  if (offset + len > data.length) return null;
  return new TextDecoder('ascii').decode(data.subarray(offset, offset + len));
}

export function tlsRecordFrame(version: [number, number], payload: Uint8Array): Uint8Array {
  const frame = new Uint8Array(5 + payload.length);
  frame[0] = 0x16;
  frame[1] = version[0];
  frame[2] = version[1];
  frame[3] = (payload.length >> 8) & 0xff;
  frame[4] = payload.length & 0xff;
  frame.set(payload, 5);
  return frame;
}

export function fixedChunks(data: Uint8Array, size: number): Uint8Array[] {
  if (data.length === 0) return [data.slice()];
  const safeSize = Math.max(1, size);
  const out: Uint8Array[] = [];
  for (let i = 0; i < data.length; i += safeSize) {
    out.push(data.slice(i, Math.min(i + safeSize, data.length)));
  }
  return out;
}

export function splitAt(data: Uint8Array, requested: number): Uint8Array[] {
  if (data.length < 2) return [data.slice()];
  const split = Math.max(1, Math.min(requested, data.length - 1));
  return [data.slice(0, split), data.slice(split)];
}

export function splitTlsRecord(data: Uint8Array, atSni: boolean): Uint8Array[] {
  if (data.length < 6 || data[0] !== 0x16) return [data.slice()];
  const payload = data.slice(5);
  if (payload.length < 2) return [data.slice()];

  let requested = Math.floor(payload.length / 2);
  if (atSni) {
    const loc = locateSni(data);
    if (loc && loc[0] > 5) {
      requested = loc[0] - 5;
    }
  }

  requested = Math.max(1, Math.min(requested, payload.length - 1));
  const version: [number, number] = [data[1]!, data[2]!];
  return [
    tlsRecordFrame(version, payload.slice(0, requested)),
    tlsRecordFrame(version, payload.slice(requested)),
  ];
}

export function rewriteFinalMaskWrites(
  data: Uint8Array,
  settings: FinalMaskSettings = DEFAULT_FINALMASK_SETTINGS,
): { firstWrite: Uint8Array; trailingWrite?: Uint8Array | undefined } {
  if (
    settings.packet !== 'tlshello' ||
    settings.length <= 0 ||
    settings.maxSplit < 2 ||
    data.length < 6 ||
    data[0] !== 0x16
  ) {
    return { firstWrite: data.slice() };
  }

  const recordLen = (data[3]! << 8) | data[4]!;
  const recordEnd = 5 + recordLen;
  if (recordLen <= settings.length || recordEnd > data.length) {
    return { firstWrite: data.slice() };
  }

  const version: [number, number] = [data[1]!, data[2]!];
  const payload = data.slice(5, recordEnd);
  const first = tlsRecordFrame(version, payload.slice(0, settings.length));
  const second = tlsRecordFrame(version, payload.slice(settings.length));

  const combined = new Uint8Array(first.length + second.length);
  combined.set(first, 0);
  combined.set(second, first.length);

  const trailing = recordEnd < data.length ? data.slice(recordEnd) : undefined;
  return { firstWrite: combined, trailingWrite: trailing };
}

export function fragment(
  data: Uint8Array,
  strategy: MultiFragmentStrategy,
  settings: FinalMaskSettings = DEFAULT_FINALMASK_SETTINGS,
): Uint8Array[] {
  switch (strategy) {
    case 'FINALMASK_TLS_HELLO': {
      const rw = rewriteFinalMaskWrites(data, settings);
      return rw.trailingWrite ? [rw.firstWrite, rw.trailingWrite] : [rw.firstWrite];
    }
    case 'FULL5':
      return fixedChunks(data, 5);
    case 'FULL10':
      return fixedChunks(data, 10);
    case 'FULL20':
      return fixedChunks(data, 20);
    case 'SNI_BOUNDARY': {
      const loc = locateSni(data);
      return loc ? splitAt(data, loc[0]) : splitAt(data, Math.floor(data.length / 2));
    }
    case 'SNI_SPLIT': {
      const loc = locateSni(data);
      return loc
        ? splitAt(data, loc[0] + Math.max(1, Math.floor(loc[1] / 2)))
        : splitAt(data, Math.floor(data.length / 2));
    }
    case 'TLS_RECORD_FRAG':
      return splitTlsRecord(data, false);
    case 'TLS_SNI_RECORDS':
      return splitTlsRecord(data, true);
    case 'HALF':
      return splitAt(data, Math.floor(data.length / 2));
    case 'RAW':
    default:
      return [data.slice()];
  }
}
