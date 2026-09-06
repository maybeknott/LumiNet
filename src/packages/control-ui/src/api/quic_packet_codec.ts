export const QuicHeaderType = {
  Initial: 0,
  ZeroRtt: 1,
  Handshake: 2,
  Retry: 3,
  OneRttShort: 4,
} as const;
export type QuicHeaderType = (typeof QuicHeaderType)[keyof typeof QuicHeaderType];

export interface QuicPacketHeader {
  headerType: QuicHeaderType;
  version: number;
  destCid: Uint8Array;
  srcCid: Uint8Array;
  packetNumber: number;
}

export class QuicPacketCodec {
  static encodeVarint(value: number): Uint8Array {
    if (value < 1 << 6) {
      return new Uint8Array([value]);
    } else if (value < 1 << 14) {
      return new Uint8Array([0x40 | ((value >> 8) & 0xff), value & 0xff]);
    } else if (value < 1 << 30) {
      return new Uint8Array([
        0x80 | ((value >>> 24) & 0xff),
        (value >>> 16) & 0xff,
        (value >>> 8) & 0xff,
        value & 0xff,
      ]);
    } else {
      // 8 bytes (value fits in safe JS double integers up to 2^53 - 1)
      const hi = Math.floor(value / 0x100000000);
      const lo = value >>> 0;
      return new Uint8Array([
        0xc0 | ((hi >>> 24) & 0xff),
        (hi >>> 16) & 0xff,
        (hi >>> 8) & 0xff,
        hi & 0xff,
        (lo >>> 24) & 0xff,
        (lo >>> 16) & 0xff,
        (lo >>> 8) & 0xff,
        lo & 0xff,
      ]);
    }
  }

  static decodeVarint(data: Uint8Array): { value: number; bytesRead: number } {
    if (data.length === 0) {
      throw new Error('Unexpected EOF reading varint');
    }

    const prefix = data[0]! >> 6;
    switch (prefix) {
      case 0:
        return { value: data[0]!, bytesRead: 1 };
      case 1: {
        if (data.length < 2) throw new Error('Varint truncated at 2 bytes');
        const val = ((data[0]! & 0x3f) << 8) | data[1]!;
        return { value: val, bytesRead: 2 };
      }
      case 2: {
        if (data.length < 4) throw new Error('Varint truncated at 4 bytes');
        const val = (data[0]! & 0x3f) * 0x1000000 + (data[1]! << 16) + (data[2]! << 8) + data[3]!;
        return { value: val, bytesRead: 4 };
      }
      case 3: {
        if (data.length < 8) throw new Error('Varint truncated at 8 bytes');
        let hi = ((data[0]! & 0x3f) << 24) | (data[1]! << 16) | (data[2]! << 8) | data[3]!;
        let lo = (data[4]! << 24) | (data[5]! << 16) | (data[6]! << 8) | data[7]!;
        const val = (hi >>> 0) * 0x100000000 + (lo >>> 0);
        return { value: val, bytesRead: 8 };
      }
      default:
        throw new Error('Invalid prefix');
    }
  }

  static encodePacket(header: QuicPacketHeader, payload: Uint8Array): Uint8Array {
    const parts: Uint8Array[] = [];

    if (header.headerType === QuicHeaderType.OneRttShort) {
      const firstByte = new Uint8Array([0x40 | 0x01]);
      parts.push(firstByte);
      parts.push(header.destCid);
      const pn = new Uint8Array([(header.packetNumber >> 8) & 0xff, header.packetNumber & 0xff]);
      parts.push(pn);
      parts.push(payload);
    } else {
      let typeBits = 0x00;
      switch (header.headerType) {
        case QuicHeaderType.Initial:
          typeBits = 0x00;
          break;
        case QuicHeaderType.ZeroRtt:
          typeBits = 0x10;
          break;
        case QuicHeaderType.Handshake:
          typeBits = 0x20;
          break;
        case QuicHeaderType.Retry:
          typeBits = 0x30;
          break;
      }
      const firstByte = new Uint8Array([0x80 | 0x40 | typeBits]);
      parts.push(firstByte);

      const ver = new Uint8Array([
        (header.version >>> 24) & 0xff,
        (header.version >>> 16) & 0xff,
        (header.version >>> 8) & 0xff,
        header.version & 0xff,
      ]);
      parts.push(ver);

      parts.push(new Uint8Array([header.destCid.length]));
      parts.push(header.destCid);

      parts.push(new Uint8Array([header.srcCid.length]));
      parts.push(header.srcCid);

      const pn = new Uint8Array([(header.packetNumber >> 8) & 0xff, header.packetNumber & 0xff]);
      const lengthVarint = this.encodeVarint(pn.length + payload.length);
      parts.push(lengthVarint);
      parts.push(pn);
      parts.push(payload);
    }

    const totalLen = parts.reduce((acc, p) => acc + p.length, 0);
    const out = new Uint8Array(totalLen);
    let offset = 0;
    for (const p of parts) {
      out.set(p, offset);
      offset += p.length;
    }
    return out;
  }

  static decodePacket(
    data: Uint8Array,
    destCidLen: number,
  ): { header: QuicPacketHeader; payload: Uint8Array } {
    if (data.length === 0) throw new Error('Empty packet');

    const firstByte = data[0]!;
    const isLongHeader = (firstByte & 0x80) !== 0;

    if (isLongHeader) {
      if (data.length < 7) throw new Error('Long header truncated');

      const typeBits = (firstByte & 0x30) >> 4;
      let headerType: QuicHeaderType;
      switch (typeBits) {
        case 0x00:
          headerType = QuicHeaderType.Initial;
          break;
        case 0x01:
          headerType = QuicHeaderType.ZeroRtt;
          break;
        case 0x02:
          headerType = QuicHeaderType.Handshake;
          break;
        case 0x03:
          headerType = QuicHeaderType.Retry;
          break;
        default:
          throw new Error('Invalid long header type');
      }

      const version = ((data[1]! << 24) | (data[2]! << 16) | (data[3]! << 8) | data[4]!) >>> 0;
      let offset = 5;

      const dcidLen = data[offset]!;
      offset += 1;
      if (offset + dcidLen > data.length) throw new Error('DCID truncated');
      const destCid = data.subarray(offset, offset + dcidLen);
      offset += dcidLen;

      if (offset >= data.length) throw new Error('SCID len truncated');
      const scidLen = data[offset]!;
      offset += 1;
      if (offset + scidLen > data.length) throw new Error('SCID truncated');
      const srcCid = data.subarray(offset, offset + scidLen);
      offset += scidLen;

      const { value: payloadLen, bytesRead: varintLen } = this.decodeVarint(data.subarray(offset));
      offset += varintLen;

      if (offset + 2 > data.length) throw new Error('Packet number truncated');
      const packetNumber = (data[offset]! << 8) | data[offset + 1]!;
      offset += 2;

      const payloadSize = Math.max(0, payloadLen - 2);
      if (offset + payloadSize > data.length) throw new Error('Payload truncated');
      const payload = data.subarray(offset, offset + payloadSize);

      return {
        header: {
          headerType,
          version,
          destCid: new Uint8Array(destCid),
          srcCid: new Uint8Array(srcCid),
          packetNumber,
        },
        payload: new Uint8Array(payload),
      };
    } else {
      let offset = 1;
      if (offset + destCidLen + 2 > data.length) throw new Error('Short header truncated');
      const destCid = data.subarray(offset, offset + destCidLen);
      offset += destCidLen;

      const packetNumber = (data[offset]! << 8) | data[offset + 1]!;
      offset += 2;

      const payload = data.subarray(offset);
      return {
        header: {
          headerType: QuicHeaderType.OneRttShort,
          version: 0,
          destCid: new Uint8Array(destCid),
          srcCid: new Uint8Array(0),
          packetNumber,
        },
        payload: new Uint8Array(payload),
      };
    }
  }
}
