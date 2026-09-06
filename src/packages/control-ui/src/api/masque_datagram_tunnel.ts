export class MasqueDatagramTunnel {
  public contextId: number;
  constructor(contextId: number = 0) {
    this.contextId = contextId;
  }

  encodeDatagram(payload: Uint8Array): Uint8Array {
    const varintBytes = this.encodeVarint(this.contextId);
    const frame = new Uint8Array(varintBytes.length + payload.length);
    frame.set(varintBytes, 0);
    frame.set(payload, varintBytes.length);
    return frame;
  }

  decodeDatagram(data: Uint8Array): { contextId: number; payload: Uint8Array } | null {
    if (data.length === 0) return null;
    const res = this.decodeVarint(data);
    if (!res) return null;
    const { val, len } = res;
    return {
      contextId: val,
      payload: data.slice(len),
    };
  }

  private encodeVarint(val: number): Uint8Array {
    if (val < 64) {
      return new Uint8Array([val]);
    } else if (val < 16384) {
      const v = 0x4000 | (val & 0x3fff);
      return new Uint8Array([(v >> 8) & 0xff, v & 0xff]);
    } else {
      const v = (0x80000000 | (val & 0x3fffffff)) >>> 0;
      const buf = new Uint8Array(4);
      const view = new DataView(buf.buffer);
      view.setUint32(0, v);
      return buf;
    }
  }

  private decodeVarint(data: Uint8Array): { val: number; len: number } | null {
    if (data.length === 0) return null;
    const first = data[0]!;
    const prefix = first >> 6;
    if (prefix === 0) {
      return { val: first & 0x3f, len: 1 };
    } else if (prefix === 1) {
      if (data.length < 2) return null;
      const val = ((first & 0x3f) << 8) | data[1]!;
      return { val, len: 2 };
    } else if (prefix === 2) {
      if (data.length < 4) return null;
      const view = new DataView(data.buffer, data.byteOffset, data.byteLength);
      const val = view.getUint32(0) & 0x3fffffff;
      return { val, len: 4 };
    }
    return null;
  }
}
