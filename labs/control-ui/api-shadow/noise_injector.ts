export interface NoisePattern {
  minPadding?: number;
  maxPadding?: number;
  headerMagic?: Uint8Array;
}

export class NoisePacketInjector {
  public readonly minPadding: number;
  public readonly maxPadding: number;
  public readonly headerMagic: Uint8Array;

  constructor(pattern: NoisePattern = {}) {
    this.minPadding = pattern.minPadding ?? 8;
    this.maxPadding = pattern.maxPadding ?? 64;
    this.headerMagic = pattern.headerMagic ?? new Uint8Array([0x17, 0x03, 0x03]);
  }

  public synthesizeNoiseFrame(seed: number): Uint8Array {
    const span = Math.max(1, this.maxPadding - this.minPadding);
    const padLen = this.minPadding + (seed % span);
    const out = new Uint8Array(this.headerMagic.length + 2 + padLen);
    out.set(this.headerMagic, 0);

    out[this.headerMagic.length] = (padLen >> 8) & 0xff;
    out[this.headerMagic.length + 1] = padLen & 0xff;

    let cur = BigInt(seed);
    const offset = this.headerMagic.length + 2;
    for (let i = 0; i < padLen; i++) {
      cur = (cur * 6364136223846793005n + 1n) & 0xffffffffffffffffn;
      out[offset + i] = Number((cur >> 32n) & 0xffn);
    }
    return out;
  }
}
