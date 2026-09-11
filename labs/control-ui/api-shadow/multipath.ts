export const MpFrameType = {
  HELLO: 1,
  HELLO_ACK: 2,
  DATA: 3,
  CLOSE: 4,
  PING: 5,
  PONG: 6,
} as const;
export type MpFrameType = (typeof MpFrameType)[keyof typeof MpFrameType];

export const MP_HEADER_LEN = 29; // 1 + 16 + 8 + 4

export interface MpFrame {
  type: MpFrameType;
  sessionId: Uint8Array;
  seq: bigint;
  payload: Uint8Array;
}

export function encodeMpFrame(frame: MpFrame): Uint8Array {
  if (frame.sessionId.length !== 16) {
    throw new Error('Session ID must be exactly 16 bytes');
  }
  const totalLen = MP_HEADER_LEN + frame.payload.length;
  const out = new Uint8Array(totalLen);
  const view = new DataView(out.buffer);

  out[0] = frame.type;
  out.set(frame.sessionId, 1);
  view.setBigUint64(17, frame.seq, false); // Big-Endian
  view.setUint32(25, frame.payload.length, false); // Big-Endian
  out.set(frame.payload, 29);

  return out;
}

export function decodeMpFrame(data: Uint8Array): MpFrame {
  if (data.length < MP_HEADER_LEN) {
    throw new Error('Buffer too short for multipath frame header');
  }
  const view = new DataView(data.buffer, data.byteOffset, data.byteLength);
  const type = data[0] as MpFrameType;
  const sessionId = data.slice(1, 17);
  const seq = view.getBigUint64(17, false);
  const payloadLen = view.getUint32(25, false);

  if (data.length < MP_HEADER_LEN + payloadLen) {
    throw new Error('Incomplete payload in multipath frame');
  }
  const payload = data.slice(MP_HEADER_LEN, MP_HEADER_LEN + payloadLen);

  return {
    type,
    sessionId,
    seq,
    payload,
  };
}

export class InOrderDedupBuffer {
  private nextSeq: bigint;
  private pending: Map<string, Uint8Array> = new Map();
  private capacity: number;

  constructor(startSeq: bigint = 0n, capacity: number = 1024) {
    this.nextSeq = startSeq;
    this.capacity = capacity;
  }

  push(seq: bigint, payload: Uint8Array): Uint8Array[] {
    if (seq < this.nextSeq || this.pending.has(seq.toString())) {
      return [];
    }
    if (this.pending.size >= this.capacity) {
      throw new Error('Dedup buffer capacity reached');
    }

    this.pending.set(seq.toString(), payload);
    const ready: Uint8Array[] = [];

    while (this.pending.has(this.nextSeq.toString())) {
      const p = this.pending.get(this.nextSeq.toString())!;
      this.pending.delete(this.nextSeq.toString());
      ready.push(p);
      this.nextSeq++;
    }

    return ready;
  }

  getNextSeq(): bigint {
    return this.nextSeq;
  }
}
