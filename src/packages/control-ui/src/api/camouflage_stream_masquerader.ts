export type MasqueradeProbeVerdict = 'ACCEPT_STREAM' | 'DEFLECT_TO_DECOY' | 'DROP_CONNECTION';

function areBytesEqual(a: Uint8Array, b: Uint8Array): boolean {
  if (a.length !== b.length) return false;
  for (let i = 0; i < a.length; i++) {
    if (a[i] !== b[i]) return false;
  }
  return true;
}

export class CamouflageStreamMasquerader {
  private validUserIds: Uint8Array[] = [];
  private sharedSecret: Uint8Array;
  public decoyHost: string;
  constructor(sharedSecret: Uint8Array, decoyHost: string) {
    this.sharedSecret = sharedSecret;
    this.decoyHost = decoyHost;
  }

  registerUser(userId: Uint8Array): void {
    const copy = new Uint8Array(16);
    copy.set(userId.subarray(0, 16));
    this.validUserIds.push(copy);
  }

  generatePreamble(userId: Uint8Array): Uint8Array {
    const out = new Uint8Array(32);
    const salt = new Uint8Array(16);
    salt.fill(0x5a);
    out.set(salt, 0);

    const secLen = this.sharedSecret.length > 0 ? this.sharedSecret.length : 1;
    for (let i = 0; i < 16; i++) {
      const secByte = this.sharedSecret.length > 0 ? this.sharedSecret[i % secLen] : 0;
      const mask = secByte! ^ salt[i]!;
      const uByte = i < userId.length ? userId[i] : 0;
      out[16 + i] = uByte! ^ mask;
    }
    return out;
  }

  inspectInboundStream(preamble: Uint8Array): MasqueradeProbeVerdict {
    if (preamble.length < 32) return 'DEFLECT_TO_DECOY';

    const salt = preamble.subarray(0, 16);
    const candidateUid = new Uint8Array(16);
    const secLen = this.sharedSecret.length > 0 ? this.sharedSecret.length : 1;

    for (let i = 0; i < 16; i++) {
      const secByte = this.sharedSecret.length > 0 ? this.sharedSecret[i % secLen] : 0;
      const mask = secByte! ^ salt[i]!;
      candidateUid[i] = preamble[16 + i]! ^ mask;
    }

    for (const valid of this.validUserIds) {
      if (areBytesEqual(valid, candidateUid)) {
        return 'ACCEPT_STREAM';
      }
    }
    return 'DEFLECT_TO_DECOY';
  }
}
