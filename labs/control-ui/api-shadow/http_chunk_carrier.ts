/**
 * HTTP Chunked Stream Carrier
 */
export class HttpChunkCarrier {
  public host: string;
  public path: string;
  public sessionId: string;
  constructor(host: string, path: string, sessionId: string) {
    this.host = host;
    this.path = path;
    this.sessionId = sessionId;
  }

  createUplinkHeader(): string {
    return `POST ${this.path} HTTP/1.1\r\nHost: ${this.host}\r\nTransfer-Encoding: chunked\r\nContent-Type: application/octet-stream\r\nX-Session-ID: ${this.sessionId}\r\nConnection: keep-alive\r\n\r\n`;
  }

  static encodeChunk(payload: Uint8Array): Uint8Array {
    const hex = payload.length.toString(16);
    const enc = new TextEncoder();
    const prefix = enc.encode(`${hex}\r\n`);
    const suffix = enc.encode('\r\n');
    const out = new Uint8Array(prefix.length + payload.length + suffix.length);
    out.set(prefix, 0);
    out.set(payload, prefix.length);
    out.set(suffix, prefix.length + payload.length);
    return out;
  }

  static decodeChunk(data: Uint8Array): { payload: Uint8Array; consumed: number } | null {
    const dec = new TextDecoder('ascii');
    const str = dec.decode(data);
    const idx = str.indexOf('\r\n');
    if (idx < 0) return null;

    const hex = str.slice(0, idx).trim();
    const size = parseInt(hex, 16);
    if (isNaN(size)) return null;

    const dataStart = idx + 2;
    const dataEnd = dataStart + size;
    const total = dataEnd + 2;
    if (data.length < total) return null;

    return {
      payload: data.slice(dataStart, dataEnd),
      consumed: total,
    };
  }
}
