export const SsrotObfsType = {
  Plain: 'plain',
  HttpSimple: 'http_simple',
  Tls12TicketAuth: 'tls12_ticket_auth',
} as const;
export type SsrotObfsType = (typeof SsrotObfsType)[keyof typeof SsrotObfsType];
export const SsrotProtocolType = {
  Origin: 'origin',
  AuthSha1V4: 'auth_sha1_v4',
  AuthChainA: 'auth_chain_a',
} as const;
export type SsrotProtocolType = (typeof SsrotProtocolType)[keyof typeof SsrotProtocolType];

export interface SsrotConfig {
  password: string;
  protocol: SsrotProtocolType;
  obfs: SsrotObfsType;
  obfsParam?: string;
}

export class SsrotStreamObfuscator {
  private sendId = 1;
  private secretKey: Uint8Array;
  public config: SsrotConfig;
  constructor(config: SsrotConfig) {
    this.config = config;
    const encoder = new TextEncoder();
    const bytes = encoder.encode(config.password);
    this.secretKey = new Uint8Array(16);
    for (let i = 0; i < 16; i++) {
      this.secretKey[i] = bytes[i % bytes.length]! ^ (i * 31);
    }
  }

  clientEncodeHandshake(targetHost: string, targetPort: number, payload: Uint8Array): Uint8Array {
    const encoder = new TextEncoder();
    const hostBytes = encoder.encode(targetHost);
    const raw = new Uint8Array(2 + hostBytes.length + 2 + payload.length);
    raw[0] = 3;
    raw[1] = hostBytes.length;
    raw.set(hostBytes, 2);
    raw[2 + hostBytes.length] = (targetPort >> 8) & 0xff;
    raw[3 + hostBytes.length] = targetPort & 0xff;
    raw.set(payload, 4 + hostBytes.length);

    const proto = this.wrapProtocol(raw);
    return this.wrapObfs(proto);
  }

  serverDecodeHandshake(data: Uint8Array): {
    host: string;
    port: number;
    payload: Uint8Array;
  } {
    const unwrappedObfs = this.unwrapObfs(data);
    const unwrappedProto = this.unwrapProtocol(unwrappedObfs);

    if (unwrappedProto.length < 4) {
      throw new Error('Handshake data too short');
    }

    const atyp = unwrappedProto[0];
    if (atyp !== 3) {
      throw new Error(`Unsupported atyp: ${atyp}`);
    }

    const hostLen = unwrappedProto[1]!;
    if (unwrappedProto.length < 2 + hostLen + 2) {
      throw new Error('Incomplete handshake host/port');
    }

    const decoder = new TextDecoder();
    const host = decoder.decode(unwrappedProto.subarray(2, 2 + hostLen));
    const port = (unwrappedProto[2 + hostLen]! << 8) | unwrappedProto[3 + hostLen]!;
    const payload = unwrappedProto.subarray(4 + hostLen);

    return { host, port, payload };
  }

  encodeChunk(data: Uint8Array): Uint8Array {
    this.sendId++;
    const chunk = new Uint8Array(6 + data.length + 4);
    chunk[0] = (data.length >> 8) & 0xff;
    chunk[1] = data.length & 0xff;
    chunk[2] = (this.sendId >> 24) & 0xff;
    chunk[3] = (this.sendId >> 16) & 0xff;
    chunk[4] = (this.sendId >> 8) & 0xff;
    chunk[5] = this.sendId & 0xff;

    for (let i = 0; i < data.length; i++) {
      const k = this.secretKey[i % this.secretKey.length]!;
      chunk[6 + i] = data[i]! ^ k;
    }

    let checksum = 0;
    for (let i = 0; i < 6 + data.length; i++) {
      checksum = (checksum + chunk[i]! * 33) & 0xffffffff;
    }
    chunk[6 + data.length] = (checksum >> 24) & 0xff;
    chunk[7 + data.length] = (checksum >> 16) & 0xff;
    chunk[8 + data.length] = (checksum >> 8) & 0xff;
    chunk[9 + data.length] = checksum & 0xff;

    return chunk;
  }

  decodeChunk(data: Uint8Array): Uint8Array {
    if (data.length < 10) {
      throw new Error('Chunk too small');
    }

    const length = (data[0]! << 8) | data[1]!;
    if (data.length < 6 + length + 4) {
      throw new Error('Incomplete chunk data');
    }

    let checksum = 0;
    for (let i = 0; i < 6 + length; i++) {
      checksum = (checksum + data[i]! * 33) & 0xffffffff;
    }
    const expectedTag = [
      (checksum >> 24) & 0xff,
      (checksum >> 16) & 0xff,
      (checksum >> 8) & 0xff,
      checksum & 0xff,
    ];
    for (let i = 0; i < 4; i++) {
      if (data[6 + length + i] !== expectedTag[i]) {
        throw new Error('Checksum verification failed');
      }
    }

    const unmasked = new Uint8Array(length);
    for (let i = 0; i < length; i++) {
      const k = this.secretKey[i % this.secretKey.length]!;
      unmasked[i] = data[6 + i]! ^ k;
    }

    return unmasked;
  }

  private wrapProtocol(data: Uint8Array): Uint8Array {
    if (this.config.protocol === SsrotProtocolType.Origin) {
      return data;
    }
    const out = new Uint8Array(8 + data.length);
    const magic = new TextEncoder().encode('SSR\x01');
    out.set(magic, 0);
    out.set([0, 0, 0, 0], 4);
    out.set(data, 8);
    return out;
  }

  private unwrapProtocol(data: Uint8Array): Uint8Array {
    if (this.config.protocol === SsrotProtocolType.Origin) {
      return data;
    }
    if (data.length < 8) {
      throw new Error('Invalid protocol header');
    }
    return data.subarray(8);
  }

  private wrapObfs(data: Uint8Array): Uint8Array {
    if (this.config.obfs === SsrotObfsType.Plain) {
      return data;
    }
    if (this.config.obfs === SsrotObfsType.HttpSimple) {
      const host = this.config.obfsParam || 'cloudflare.com';
      const header = `GET / HTTP/1.1\r\nHost: ${host}\r\nContent-Length: ${data.length}\r\n\r\n`;
      const hBytes = new TextEncoder().encode(header);
      const out = new Uint8Array(hBytes.length + data.length);
      out.set(hBytes, 0);
      out.set(data, hBytes.length);
      return out;
    }
    // TLS12TicketAuth
    const out = new Uint8Array(5 + data.length);
    out[0] = 0x16;
    out[1] = 0x03;
    out[2] = 0x03;
    out[3] = (data.length >> 8) & 0xff;
    out[4] = data.length & 0xff;
    out.set(data, 5);
    return out;
  }

  private unwrapObfs(data: Uint8Array): Uint8Array {
    if (this.config.obfs === SsrotObfsType.Plain) {
      return data;
    }
    if (this.config.obfs === SsrotObfsType.HttpSimple) {
      const text = new TextDecoder().decode(data);
      const idx = text.indexOf('\r\n\r\n');
      if (idx === -1) {
        throw new Error('Invalid HTTP simple framing');
      }
      return data.subarray(idx + 4);
    }
    if (data.length < 5 || data[0] !== 0x16) {
      throw new Error('Invalid TLS record framing');
    }
    const len = (data[3]! << 8) | data[4]!;
    return data.subarray(5, 5 + len);
  }
}
