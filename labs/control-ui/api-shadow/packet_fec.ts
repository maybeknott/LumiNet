/**
 * Packet Forward Error Correction (FEC) Engine
 */
export class PacketFecEncoder {
  public groupSize: number;
  constructor(groupSize: number = 4) {
    this.groupSize = groupSize;
  }

  computeParity(sources: Uint8Array[]): Uint8Array {
    if (sources.length === 0) return new Uint8Array(0);
    const maxLen = Math.max(...sources.map((s) => s.length));
    const parity = new Uint8Array(maxLen);

    for (const src of sources) {
      for (let i = 0; i < src.length; i++) {
        parity[i]! ^= src[i]!;
      }
    }
    return parity;
  }

  static recoverSingleMissing(
    knownSources: Uint8Array[],
    parity: Uint8Array,
    expectedLen: number,
  ): Uint8Array {
    const rec = new Uint8Array(parity);
    for (const src of knownSources) {
      for (let i = 0; i < src.length; i++) {
        if (i < rec.length) rec[i]! ^= src[i]!;
      }
    }
    return rec.slice(0, expectedLen);
  }
}
