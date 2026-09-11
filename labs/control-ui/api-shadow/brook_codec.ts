export const BrookTargetType = {
  IPv4: 1,
  Domain: 2,
  IPv6: 3,
} as const;
export type BrookTargetType = (typeof BrookTargetType)[keyof typeof BrookTargetType];

export interface BrookRequest {
  targetType: BrookTargetType;
  host: string;
  port: number;
}

export class BrookCodec {
  public static encodeRequest(req: BrookRequest): Uint8Array {
    const enc = new TextEncoder();
    const hostBytes = enc.encode(req.host);
    const out = new Uint8Array(8 + 1 + 1 + hostBytes.length + 2);
    // 8-byte nonce
    crypto.getRandomValues(out.subarray(0, 8));
    out[8] = req.targetType;
    out[9] = hostBytes.length;
    out.set(hostBytes, 10);
    const pPos = 10 + hostBytes.length;
    out[pPos] = (req.port >> 8) & 0xff;
    out[pPos + 1] = req.port & 0xff;
    return out;
  }

  public static decodeRequest(data: Uint8Array): BrookRequest | null {
    if (data.length < 12) return null;
    const targetType = (data[8] ?? 1) as BrookTargetType;
    const hLen = data[9] ?? 0;
    if (data.length < 10 + hLen + 2) return null;
    const dec = new TextDecoder();
    const host = dec.decode(data.slice(10, 10 + hLen));
    const pPos = 10 + hLen;
    const port = ((data[pPos] ?? 0) << 8) | (data[pPos + 1] ?? 0);
    return { targetType, host, port };
  }
}
