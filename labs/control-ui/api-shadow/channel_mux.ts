export const ChannelOpcode = {
  Open: 1,
  Data: 2,
  Close: 3,
  Ack: 4,
} as const;
export type ChannelOpcode = (typeof ChannelOpcode)[keyof typeof ChannelOpcode];

export interface ChannelMuxFrame {
  channelId: number;
  opcode: ChannelOpcode;
  payload: Uint8Array;
}

export class ChannelMuxCodec {
  public static encode(frame: ChannelMuxFrame): Uint8Array {
    const out = new Uint8Array(7 + frame.payload.length);
    const view = new DataView(out.buffer);
    view.setUint32(0, frame.channelId, false);
    out[4] = frame.opcode;
    view.setUint16(5, frame.payload.length, false);
    out.set(frame.payload, 7);
    return out;
  }

  public static decode(data: Uint8Array): ChannelMuxFrame | null {
    if (data.length < 7) return null;
    const view = new DataView(data.buffer, data.byteOffset, data.byteLength);
    const channelId = view.getUint32(0, false);
    const opcode = (data[4] ?? 1) as ChannelOpcode;
    const len = view.getUint16(5, false);
    if (data.length < 7 + len) return null;
    return {
      channelId,
      opcode,
      payload: data.slice(7, 7 + len),
    };
  }
}
