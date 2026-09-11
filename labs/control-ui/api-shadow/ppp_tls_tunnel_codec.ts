export class PppTlsTunnelCodec {
  public enableHdlc: boolean;
  constructor(enableHdlc: boolean = true) {
    this.enableHdlc = enableHdlc;
  }

  encodeFrame(proto: number, payload: Uint8Array): Uint8Array {
    const hdlcLen = this.enableHdlc ? 2 : 0;
    const bodyLen = hdlcLen + 2 + payload.length;
    const frame = new Uint8Array(2 + bodyLen);
    const view = new DataView(frame.buffer, frame.byteOffset, frame.byteLength);

    view.setUint16(0, bodyLen);
    let offset = 2;
    if (this.enableHdlc) {
      frame[offset] = 0xff;
      frame[offset + 1] = 0x03;
      offset += 2;
    }

    view.setUint16(offset, proto);
    offset += 2;
    frame.set(payload, offset);
    return frame;
  }

  decodeFrame(data: Uint8Array): { proto: number; payload: Uint8Array } | null {
    if (data.length < 2) return null;
    const view = new DataView(data.buffer, data.byteOffset, data.byteLength);
    const bodyLen = view.getUint16(0);
    if (data.length < 2 + bodyLen) return null;

    let offset = 2;
    if (this.enableHdlc) {
      if (bodyLen < 2) return null;
      if (data[offset] !== 0xff || data[offset + 1] !== 0x03) return null;
      offset += 2;
    }

    if (bodyLen < (this.enableHdlc ? 4 : 2)) return null;
    const proto = view.getUint16(offset);
    offset += 2;

    const payloadLen = 2 + bodyLen - offset;
    const payload = data.slice(offset, offset + payloadLen);
    return { proto, payload };
  }
}
