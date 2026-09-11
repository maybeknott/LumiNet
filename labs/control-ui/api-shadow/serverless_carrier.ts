export interface ServerlessPacket {
  streamId: number;
  isEof: boolean;
  data: Uint8Array;
}

export class ServerlessCarrierCodec {
  static readonly MAGIC = 0x534c5353; // "SLSS"

  static encode(packet: ServerlessPacket): Uint8Array {
    const len = packet.data.length;
    const buf = new Uint8Array(13 + len);
    const view = new DataView(buf.buffer);

    view.setUint32(0, ServerlessCarrierCodec.MAGIC, false);
    view.setUint32(4, packet.streamId, false);
    buf[8] = packet.isEof ? 1 : 0;
    view.setUint32(9, len, false);
    buf.set(packet.data, 13);

    return buf;
  }

  static decode(buf: Uint8Array): ServerlessPacket {
    if (buf.length < 13) throw new Error("frame too short");
    const view = new DataView(buf.buffer, buf.byteOffset, buf.byteLength);
    const magic = view.getUint32(0, false);
    if (magic !== ServerlessCarrierCodec.MAGIC) throw new Error("invalid serverless magic");

    const streamId = view.getUint32(4, false);
    const isEof = buf[8] === 1;
    const len = view.getUint32(9, false);
    const data = buf.slice(13, 13 + len);

    return { streamId, isEof, data };
  }
}
