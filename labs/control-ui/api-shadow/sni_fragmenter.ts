/**
 * 3-Zone TLS SNI Fragmentation & DPI Evasion API.
 *
 * Ported and unified from `bepass-main`.
 * Provides packet inspection, 3-zone SNI decomposition, and fragment delay scheduling.
 */

export interface SniFragmentConfig {
  beforeSniRange: [number, number];
  sniRange: [number, number];
  afterSniRange: [number, number];
  delayMsRange: [number, number];
}

export function defaultSniFragmentConfig(): SniFragmentConfig {
  return {
    beforeSniRange: [1, 5],
    sniRange: [1, 3],
    afterSniRange: [5, 20],
    delayMsRange: [1, 5],
  };
}

export interface FragmentSlice {
  zone: 'before_sni' | 'sni' | 'after_sni' | 'passthrough';
  payload: Uint8Array;
  delayMs: number;
}

export interface SniFragmentPlan {
  slices: FragmentSlice[];
  totalBytes: number;
  detectedSni: string | null;
}

export class SniFragmenter {
  /**
   * Locates the SNI extension boundaries inside a TLS ClientHello packet.
   */
  public static locateSni(packet: Uint8Array): { start: number; end: number; sni: string } | null {
    if (packet.length < 5 + 4 + 2 + 32 + 1) {
      return null;
    }

    // Record header: ContentType 0x16 = Handshake
    if (packet[0] !== 0x16) {
      return null;
    }

    const recordLen = (packet[3]! << 8) | packet[4]!;
    if (packet.length < 5 + recordLen) {
      return null;
    }

    let offset = 5;
    // Handshake type 0x01 = ClientHello
    if (packet[offset] !== 0x01) {
      return null;
    }

    const handshakeLen =
      (packet[offset + 1]! << 16) | (packet[offset + 2]! << 8) | packet[offset + 3]!;
    if (packet.length < offset + 4 + handshakeLen) {
      return null;
    }
    offset += 4;

    // Version (2) + Random (32)
    if (packet.length < offset + 2 + 32 + 1) {
      return null;
    }
    offset += 2 + 32;

    // Session ID
    const sessionIdLen = packet[offset]!;
    offset += 1;
    if (packet.length < offset + sessionIdLen + 2) {
      return null;
    }
    offset += sessionIdLen;

    // Cipher Suites
    const cipherSuitesLen = (packet[offset]! << 8) | packet[offset + 1]!;
    offset += 2;
    if (packet.length < offset + cipherSuitesLen + 1) {
      return null;
    }
    offset += cipherSuitesLen;

    // Compression Methods
    const compressionLen = packet[offset]!;
    offset += 1;
    if (packet.length < offset + compressionLen + 2) {
      return null;
    }
    offset += compressionLen;

    // Extensions
    const extensionsLen = (packet[offset]! << 8) | packet[offset + 1]!;
    offset += 2;
    const extensionsEnd = offset + extensionsLen;
    if (packet.length < extensionsEnd) {
      return null;
    }

    while (offset + 4 <= extensionsEnd) {
      const extType = (packet[offset]! << 8) | packet[offset + 1]!;
      const extLen = (packet[offset + 2]! << 8) | packet[offset + 3]!;
      offset += 4;

      if (offset + extLen > extensionsEnd) {
        break;
      }

      if (extType === 0x0000) {
        // Server Name Indication
        if (extLen < 5) return null;
        const listLen = (packet[offset]! << 8) | packet[offset + 1]!;
        let listOff = offset + 2;
        const listEnd = offset + 2 + listLen;

        while (listOff + 3 <= listEnd) {
          const nameType = packet[listOff];
          const nameLen = (packet[listOff + 1]! << 8) | packet[listOff + 2]!;
          listOff += 3;

          if (listOff + nameLen > listEnd) {
            break;
          }

          if (nameType === 0x00) {
            // Hostname
            const nameBytes = packet.subarray(listOff, listOff + nameLen);
            const decoder = new TextDecoder('utf-8');
            const sni = decoder.decode(nameBytes);
            return {
              start: listOff,
              end: listOff + nameLen,
              sni,
            };
          }
          listOff += nameLen;
        }
      }
      offset += extLen;
    }

    return null;
  }

  /**
   * Plans the 3-zone fragment slices and jitter delays for a raw TLS or generic packet.
   */
  public static planFragments(
    packet: Uint8Array,
    config: SniFragmentConfig = defaultSniFragmentConfig(),
  ): SniFragmentPlan {
    const sniLoc = this.locateSni(packet);
    if (!sniLoc || sniLoc.end <= sniLoc.start) {
      return {
        slices: [
          {
            zone: 'passthrough',
            payload: new Uint8Array(packet),
            delayMs: 0,
          },
        ],
        totalBytes: packet.length,
        detectedSni: null,
      };
    }

    const slices: FragmentSlice[] = [];

    // Zone 0: Before SNI
    this.chunkZone(
      packet.subarray(0, sniLoc.start),
      config.beforeSniRange,
      config.delayMsRange,
      'before_sni',
      slices,
    );

    // Zone 1: SNI Hostname
    this.chunkZone(
      packet.subarray(sniLoc.start, sniLoc.end),
      config.sniRange,
      config.delayMsRange,
      'sni',
      slices,
    );

    // Zone 2: After SNI
    this.chunkZone(
      packet.subarray(sniLoc.end),
      config.afterSniRange,
      config.delayMsRange,
      'after_sni',
      slices,
    );

    const totalBytes = slices.reduce((acc, cur) => acc + cur.payload.length, 0);

    return {
      slices,
      totalBytes,
      detectedSni: sniLoc.sni,
    };
  }

  private static chunkZone(
    data: Uint8Array,
    range: [number, number],
    delayRange: [number, number],
    zone: 'before_sni' | 'sni' | 'after_sni',
    out: FragmentSlice[],
  ): void {
    if (data.length === 0) return;

    let [minChunk, maxChunk] = range;
    if (minChunk <= 0) minChunk = 1;
    if (maxChunk < minChunk) maxChunk = minChunk;

    let [minDelay, maxDelay] = delayRange;
    if (minDelay < 0) minDelay = 0;
    if (maxDelay < minDelay) maxDelay = minDelay;

    const span = maxChunk - minChunk + 1;
    const delaySpan = maxDelay - minDelay + 1;

    let offset = 0;
    let step = 0;

    while (offset < data.length) {
      const chunkSize = minChunk + (step % span);
      const end = Math.min(offset + chunkSize, data.length);
      const delayMs = minDelay + (step % delaySpan);

      out.push({
        zone,
        payload: data.slice(offset, end),
        delayMs,
      });

      offset = end;
      step++;
    }
  }

  /**
   * Simulates timed packet transmission through the fragment plan.
   */
  public static async simulateFragmentTransmission(
    plan: SniFragmentPlan,
  ): Promise<{ sentSlices: number; totalBytes: number; durationMs: number }> {
    let sentSlices = 0;
    let totalBytes = 0;
    let durationMs = 0;

    for (const slice of plan.slices) {
      sentSlices++;
      totalBytes += slice.payload.length;
      durationMs += slice.delayMs;
    }

    return { sentSlices, totalBytes, durationMs };
  }
}
