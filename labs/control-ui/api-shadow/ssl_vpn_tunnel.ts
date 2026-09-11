export interface SslVpnFrame {
  sessionId: number;
  payload: Uint8Array;
}

export class SslVpnTunnelCodec {
  public static readonly MAGIC = 0x53534C56; // 'SSLV'

  public static encode(frame: SslVpnFrame): Uint8Array {
    const out = new Uint8Array(12 + frame.payload.length);
    const view = new DataView(out.buffer);
    view.setUint32(0, this.MAGIC, false);
    view.setUint32(4, frame.sessionId, false);
    view.setUint32(8, frame.payload.length, false);
    out.set(frame.payload, 12);
    return out;
  }

  public static decode(data: Uint8Array): SslVpnFrame | null {
    if (data.length < 12) return null;
    const view = new DataView(data.buffer, data.byteOffset, data.byteLength);
    if (view.getUint32(0, false) !== this.MAGIC) return null;
    const sessionId = view.getUint32(4, false);
    const len = view.getUint32(8, false);
    if (data.length < 12 + len) return null;
    return {
      sessionId,
      payload: data.slice(12, 12 + len)
    };
  }
}
