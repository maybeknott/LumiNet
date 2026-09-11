export class RawPacketCarrierUI {
  static readonly MAGIC = 0x50514554; // "PQET"

  static computeChecksum(payload: Uint8Array): number {
    let sum = 0;
    for (let i = 0; i < payload.length - 1; i += 2) {
      sum += (payload[i]! << 8) | payload[i + 1]!;
    }
    if (payload.length % 2 === 1) {
      sum += payload[payload.length - 1]! << 8;
    }
    while (sum > 0xffff) {
      sum = (sum & 0xffff) + (sum >>> 16);
    }
    return ~sum & 0xffff;
  }

  static frame(seq: number, sessionId: number, payload: Uint8Array): Uint8Array {
    const csum = this.computeChecksum(payload);
    const buf = new Uint8Array(16 + payload.length);
    const view = new DataView(buf.buffer);

    view.setUint32(0, this.MAGIC, false);
    view.setUint32(4, seq, false);
    view.setUint32(8, sessionId, false);
    view.setUint16(12, csum, false);
    view.setUint16(14, payload.length, false);
    buf.set(payload, 16);

    return buf;
  }
}
