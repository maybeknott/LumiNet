/**
 * DPI Pattern Masker and Fragmenter
 */
export class DpiPatternMasker {
  static readonly FAKE_ALERT = new Uint8Array([0x15, 0x03, 0x03, 0x00, 0x02, 0x01, 0x00]);
  public splitOffset: number;
  public insertNoiseRecord: boolean;
  constructor(splitOffset: number = 5, insertNoiseRecord: boolean = true) {
    this.splitOffset = splitOffset;
    this.insertNoiseRecord = insertNoiseRecord;
  }

  fragmentPayload(payload: Uint8Array): Uint8Array[] {
    if (payload.length <= this.splitOffset) return [payload];
    const frags: Uint8Array[] = [];

    if (
      this.insertNoiseRecord &&
      payload.length >= 2 &&
      payload[0] === 0x16 &&
      payload[1] === 0x03
    ) {
      frags.push(new Uint8Array(DpiPatternMasker.FAKE_ALERT));
    }

    const splitAt = Math.min(this.splitOffset, payload.length - 1);
    frags.push(payload.slice(0, splitAt));
    frags.push(payload.slice(splitAt));
    return frags;
  }

  static reassemblePayload(fragments: Uint8Array[]): Uint8Array {
    let totalLen = 0;
    const valid: Uint8Array[] = [];

    for (const f of fragments) {
      if (
        f.length === DpiPatternMasker.FAKE_ALERT.length &&
        f.every((b, i) => b === DpiPatternMasker.FAKE_ALERT[i])
      ) {
        continue;
      }
      valid.push(f);
      totalLen += f.length;
    }

    const out = new Uint8Array(totalLen);
    let offset = 0;
    for (const v of valid) {
      out.set(v, offset);
      offset += v.length;
    }
    return out;
  }
}
