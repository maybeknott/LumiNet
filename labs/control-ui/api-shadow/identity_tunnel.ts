export interface IdentityTunnelHeader {
  version: number;
  targetPort: number;
  authTokenHex: string;
  targetDomain: string;
}

export class IdentityTunnelCodec {
  public static readonly MAGIC = 'PANG';

  public static encode(targetPort: number, tokenHex: string, domain: string): Uint8Array {
    const enc = new TextEncoder();
    const domainBytes = enc.encode(domain);
    const magicBytes = enc.encode(this.MAGIC);

    const out = new Uint8Array(4 + 1 + 2 + 32 + 1 + domainBytes.length);
    out.set(magicBytes, 0);
    out[4] = 1; // version
    out[5] = (targetPort >> 8) & 0xff;
    out[6] = targetPort & 0xff;

    // Fill 32-byte token from hex
    for (let i = 0; i < 32; i++) {
      out[7 + i] = parseInt(tokenHex.substr(i * 2, 2) || '00', 16);
    }
    out[39] = domainBytes.length;
    out.set(domainBytes, 40);
    return out;
  }

  public static decode(data: Uint8Array): IdentityTunnelHeader | null {
    if (data.length < 40) return null;
    const dec = new TextDecoder();
    const magic = dec.decode(data.slice(0, 4));
    if (magic !== this.MAGIC) return null;
    const version = data[4] ?? 1;
    const p1 = data[5] ?? 0;
    const p2 = data[6] ?? 0;
    const targetPort = (p1 << 8) | p2;

    const tokenSlice = data.slice(7, 39);
    const authTokenHex = Array.from(tokenSlice).map(b => b.toString(16).padStart(2, '0')).join('');
    const dLen = data[39] ?? 0;
    if (data.length < 40 + dLen) return null;
    const targetDomain = dec.decode(data.slice(40, 40 + dLen));

    return { version, targetPort, authTokenHex, targetDomain };
  }
}
