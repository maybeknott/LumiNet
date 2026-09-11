/**
 * Adaptive Strategy Racer & Disposable Fake SNI Probe Engine
 * Originates from UAC-SNI-Spoofer-Windows-main and adapted for LumiNet Control UI.
 */

import { locateSni, fixedChunks, splitAt, splitTlsRecord } from './multi_strategy_fragmenter';

export type ExtendedFragmentStrategy =
  | 'SNI_CHARS'
  | 'MULTI64'
  | 'FULL5'
  | 'FULL10'
  | 'FULL20'
  | 'SNI_BOUNDARY'
  | 'SNI_SPLIT'
  | 'TLS_RECORD_FRAG'
  | 'TLS_SNI_RECORDS'
  | 'HALF'
  | 'RAW';

export type StrategyResponseStatus =
  'VALID' | 'EMPTY_RESPONSE' | 'ALERT_REJECTED' | 'TRUNCATED_MALFORMED';

export interface StrategyPlanEntry {
  strategy: ExtendedFragmentStrategy;
  delayMs: number;
}

export type CarrierMode = 'MCI' | 'IRANCELL' | 'ADAPTIVE';

export function validateStrategyResponse(
  response: Uint8Array | null | undefined,
): StrategyResponseStatus {
  if (!response || response.length === 0) {
    return 'EMPTY_RESPONSE';
  }
  const first = response[0];
  if (first === 0x15) {
    return 'ALERT_REJECTED';
  }
  if (response.length < 8 && (first === 0x14 || first === 0x16 || first === 0x17)) {
    return 'TRUNCATED_MALFORMED';
  }
  return 'VALID';
}

export function fragmentExtended(
  data: Uint8Array,
  strategy: ExtendedFragmentStrategy,
  chunkSize: number = 64,
): Uint8Array[] {
  if (data.length < 2) return [data.slice()];
  const location = locateSni(data);

  switch (strategy) {
    case 'RAW':
      return [data.slice()];
    case 'HALF':
      return splitAt(data, Math.floor(data.length / 2));
    case 'FULL5':
      return fixedChunks(data, 5);
    case 'FULL10':
      return fixedChunks(data, 10);
    case 'FULL20':
      return fixedChunks(data, 20);
    case 'MULTI64':
      return fixedChunks(data, chunkSize > 0 ? chunkSize : 64);
    case 'SNI_BOUNDARY':
      return location ? splitAt(data, location[0]) : splitAt(data, Math.floor(data.length / 2));
    case 'SNI_SPLIT':
      return location
        ? splitAt(data, location[0] + Math.max(1, Math.floor(location[1] / 2)))
        : splitAt(data, Math.floor(data.length / 2));
    case 'SNI_CHARS': {
      if (!location) {
        return splitAt(data, Math.floor(data.length / 2));
      }
      const [start, length] = location;
      const out: Uint8Array[] = [];
      if (start > 0) {
        out.push(data.slice(0, start));
      }
      for (let i = 0; i < length; i++) {
        out.push(data.slice(start + i, start + i + 1));
      }
      if (start + length < data.length) {
        out.push(data.slice(start + length));
      }
      return out;
    }
    case 'TLS_RECORD_FRAG':
      return splitTlsRecord(data, false);
    case 'TLS_SNI_RECORDS':
      return splitTlsRecord(data, true);
    default:
      return [data.slice()];
  }
}

export function buildDisposableFakeProbe(fakeSni: string): Uint8Array {
  const hostBytes = new TextEncoder().encode(fakeSni);
  const pkt: number[] = [];

  // Record Header
  pkt.push(0x16, 0x03, 0x01, 0x00, 0x00);

  const handshakeStart = pkt.length;
  pkt.push(0x01, 0x00, 0x00, 0x00); // ClientHello
  pkt.push(0x03, 0x03); // TLS 1.2

  for (let i = 0; i < 32; i++) {
    pkt.push((i * 37 + 11) & 0xff);
  }
  pkt.push(0x00); // Session ID len 0

  // Cipher Suites
  pkt.push(0x00, 0x04, 0x13, 0x01, 0x13, 0x03);
  pkt.push(0x01, 0x00); // Compression null

  const extLenPos = pkt.length;
  pkt.push(0x00, 0x00);
  const extStart = pkt.length;

  // SNI Extension
  const sniExtLen = 2 + 1 + 2 + hostBytes.length;
  pkt.push(0x00, 0x00, (sniExtLen >> 8) & 0xff, sniExtLen & 0xff);
  const listLen = 1 + 2 + hostBytes.length;
  pkt.push(
    (listLen >> 8) & 0xff,
    listLen & 0xff,
    0x00,
    (hostBytes.length >> 8) & 0xff,
    hostBytes.length & 0xff,
  );
  pkt.push(...hostBytes);

  // ALPN Extension (http/1.1, h2)
  pkt.push(
    0x00,
    0x10,
    0x00,
    0x0e,
    0x00,
    0x0c,
    0x08,
    0x68,
    0x74,
    0x74,
    0x70,
    0x2f,
    0x31,
    0x2e,
    0x31, // http/1.1
    0x02,
    0x68,
    0x32, // h2
  );

  const extLen = pkt.length - extStart;
  pkt[extLenPos] = (extLen >> 8) & 0xff;
  pkt[extLenPos + 1] = extLen & 0xff;

  const hsLen = pkt.length - handshakeStart - 4;
  pkt[handshakeStart + 1] = (hsLen >> 16) & 0xff;
  pkt[handshakeStart + 2] = (hsLen >> 8) & 0xff;
  pkt[handshakeStart + 3] = hsLen & 0xff;

  const recLen = pkt.length - 5;
  pkt[3] = (recLen >> 8) & 0xff;
  pkt[4] = recLen & 0xff;

  return new Uint8Array(pkt);
}

export class AdaptiveStrategyRacer {
  private preferredStrategies: Map<string, ExtendedFragmentStrategy> = new Map();
  public carrierMode: CarrierMode;
  public fakeSni: string;
  public fakeProbeEnabled: boolean;
  constructor(
    carrierMode: CarrierMode = 'ADAPTIVE',
    fakeSni: string = 'www.speedtest.net',
    fakeProbeEnabled: boolean = true,
  ) {
    this.carrierMode = carrierMode;
    this.fakeSni = fakeSni;
    this.fakeProbeEnabled = fakeProbeEnabled;
  }

  planStrategies(host: string): StrategyPlanEntry[] {
    let base: StrategyPlanEntry[] = [];
    switch (this.carrierMode) {
      case 'MCI':
        base = [
          { strategy: 'FULL20', delayMs: 1 },
          { strategy: 'FULL10', delayMs: 2 },
          { strategy: 'FULL5', delayMs: 5 },
          { strategy: 'SNI_CHARS', delayMs: 2 },
          { strategy: 'SNI_BOUNDARY', delayMs: 1 },
          { strategy: 'SNI_SPLIT', delayMs: 3 },
          { strategy: 'TLS_RECORD_FRAG', delayMs: 3 },
          { strategy: 'TLS_SNI_RECORDS', delayMs: 3 },
          { strategy: 'HALF', delayMs: 3 },
          { strategy: 'RAW', delayMs: 0 },
        ];
        break;
      case 'IRANCELL':
        base = [
          { strategy: 'MULTI64', delayMs: 0 },
          { strategy: 'SNI_BOUNDARY', delayMs: 0 },
          { strategy: 'TLS_RECORD_FRAG', delayMs: 1 },
          { strategy: 'SNI_CHARS', delayMs: 1 },
          { strategy: 'SNI_SPLIT', delayMs: 2 },
          { strategy: 'HALF', delayMs: 2 },
          { strategy: 'RAW', delayMs: 0 },
        ];
        break;
      case 'ADAPTIVE':
      default:
        base = [
          { strategy: 'SNI_SPLIT', delayMs: 2 },
          { strategy: 'SNI_BOUNDARY', delayMs: 1 },
          { strategy: 'SNI_CHARS', delayMs: 1 },
          { strategy: 'TLS_SNI_RECORDS', delayMs: 2 },
          { strategy: 'TLS_RECORD_FRAG', delayMs: 2 },
          { strategy: 'MULTI64', delayMs: 0 },
          { strategy: 'HALF', delayMs: 2 },
          { strategy: 'RAW', delayMs: 0 },
        ];
        break;
    }

    const preferred = this.preferredStrategies.get(host);
    if (!preferred) return base;

    const prioritized: StrategyPlanEntry[] = [];
    const others: StrategyPlanEntry[] = [];
    for (const entry of base) {
      if (entry.strategy === preferred) {
        prioritized.push(entry);
      } else {
        others.push(entry);
      }
    }
    return [...prioritized, ...others];
  }

  recordSuccess(host: string, strategy: ExtendedFragmentStrategy): void {
    this.preferredStrategies.set(host, strategy);
  }

  preferredStrategy(host: string): ExtendedFragmentStrategy | undefined {
    return this.preferredStrategies.get(host);
  }

  buildFakeProbe(): Uint8Array | null {
    if (!this.fakeProbeEnabled || !this.fakeSni) return null;
    return buildDisposableFakeProbe(this.fakeSni);
  }
}
