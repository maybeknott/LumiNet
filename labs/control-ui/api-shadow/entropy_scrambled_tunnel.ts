export class EntropyScrambledTunnel {
  public minPadding: number;
  public maxPadding: number;
  private secretKey: Uint8Array;
  constructor(secretKey: Uint8Array, minPad: number = 8, maxPad: number = 32) {
    this.secretKey = secretKey;
    this.minPadding = Math.max(4, minPad);
    this.maxPadding = Math.max(this.minPadding + 8, maxPad);
  }

  scramblePacket(payload: Uint8Array, seed: number): Uint8Array {
    const padRange = this.maxPadding - this.minPadding;
    const padLen = this.minPadding + (Math.abs(seed) % padRange);
    const totalLen = 4 + payload.length + padLen;

    const frame = new Uint8Array(totalLen);
    const view = new DataView(frame.buffer, frame.byteOffset, frame.byteLength);
    view.setUint16(0, payload.length);
    view.setUint16(2, padLen);
    frame.set(payload, 4);

    for (let i = 0; i < padLen; i++) {
      frame[4 + payload.length + i] = Math.floor(Math.random() * 256);
    }

    this.applyMask(frame, seed);
    return frame;
  }

  descramblePacket(scrambled: Uint8Array, seed: number): Uint8Array | null {
    if (scrambled.length < 4) return null;
    const unmasked = new Uint8Array(scrambled);
    this.applyMask(unmasked, seed);

    const view = new DataView(unmasked.buffer, unmasked.byteOffset, unmasked.byteLength);
    const payloadLen = view.getUint16(0);
    const padLen = view.getUint16(2);

    if (unmasked.length < 4 + payloadLen + padLen) return null;
    return unmasked.slice(4, 4 + payloadLen);
  }

  private applyMask(data: Uint8Array, seed: number): void {
    let s = BigInt(seed);
    const multiplier = 6364136223846793005n;
    const increment = 1442695040888963407n;
    for (let i = 0; i < data.length; i++) {
      s = (s * multiplier + increment) & 0xffffffffffffffffn;
      const mask = Number((s >> 33n) & 0xffn) ^ this.secretKey[i % this.secretKey.length]!;
      data[i]! ^= mask;
    }
  }

  static calculateEntropy(data: Uint8Array): number {
    if (data.length === 0) return 0;
    const counts = new Array(256).fill(0);
    for (let i = 0; i < data.length; i++) {
      counts[data[i]!]++;
    }
    const total = data.length;
    let entropy = 0;
    for (let i = 0; i < 256; i++) {
      if (counts[i] > 0) {
        const p = counts[i] / total;
        entropy -= p * Math.log2(p);
      }
    }
    return entropy;
  }
}
