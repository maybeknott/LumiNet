/**
 * Covert Storage Multiplex Stream Framer
 */
export interface CovertChunk {
  streamId: number;
  sequence: number;
  isFin: boolean;
  payload: Uint8Array;
}

export class CovertStorageFramer {
  static readonly MAGIC = new Uint8Array([0x53, 0x4b, 0x52, 0x4b]); // "SKRK"

  static frameChunk(chunk: CovertChunk): Uint8Array {
    const total = 22 + chunk.payload.length;
    const out = new Uint8Array(total);
    const view = new DataView(out.buffer);

    out.set(CovertStorageFramer.MAGIC, 0);
    view.setUint32(4, chunk.streamId, false);
    view.setBigUint64(8, BigInt(chunk.sequence), false);
    view.setUint8(16, chunk.isFin ? 1 : 0);
    view.setUint32(17, chunk.payload.length, false);
    view.setUint8(21, CovertStorageFramer.computeCrc8(chunk.payload));
    out.set(chunk.payload, 22);

    return out;
  }

  static unframeChunk(buf: Uint8Array): CovertChunk | null {
    if (buf.length < 22) return null;
    for (let i = 0; i < 4; i++) {
      if (buf[i] !== CovertStorageFramer.MAGIC[i]) return null;
    }

    const view = new DataView(buf.buffer, buf.byteOffset, buf.byteLength);
    const streamId = view.getUint32(4, false);
    const sequence = Number(view.getBigUint64(8, false));
    const isFin = view.getUint8(16) !== 0;
    const payloadLen = view.getUint32(17, false);
    const expectedCrc = view.getUint8(21);

    if (buf.length < 22 + payloadLen) return null;
    const payload = buf.slice(22, 22 + payloadLen);
    if (CovertStorageFramer.computeCrc8(payload) !== expectedCrc) return null;

    return { streamId, sequence, isFin, payload };
  }

  private static computeCrc8(data: Uint8Array): number {
    let crc = 0;
    for (let i = 0; i < data.length; i++) {
      crc ^= data[i]!;
      for (let j = 0; j < 8; j++) {
        crc = (crc & 0x80) !== 0 ? (crc << 1) ^ 0x07 : crc << 1;
      }
    }
    return crc & 0xff;
  }
}
