export class OverTlsCodec {
  public maxPadding: number;
  constructor(maxPadding: number = 32) {
    this.maxPadding = maxPadding;
  }

  encodeFrame(payload: Uint8Array, paddingLen: number): Uint8Array {
    const pLen = Math.min(paddingLen, this.maxPadding);
    const nLen = payload.length;
    const total = 6 + nLen + pLen;
    const buf = new Uint8Array(total);

    // Magic 0x544F ('OT')
    buf[0] = 0x54;
    buf[1] = 0x4f;
    buf[2] = 0x01; // Data frame
    buf[3] = pLen;
    buf[4] = (nLen >> 8) & 0xff;
    buf[5] = nLen & 0xff;

    buf.set(payload, 6);
    for (let i = 0; i < pLen; i++) {
      buf[6 + nLen + i] = ((i * 37) ^ 0xa5) & 0xff;
    }
    return buf;
  }

  decodeFrame(buf: Uint8Array): Uint8Array | null {
    if (buf.length < 6) return null;
    if (buf[0] !== 0x54 || buf[1] !== 0x4f) return null;

    const pLen = buf[3]!;
    const nLen = (buf[4]! << 8) | buf[5]!;
    if (buf.length < 6 + nLen + pLen) return null;

    return buf.slice(6, 6 + nLen);
  }
}
