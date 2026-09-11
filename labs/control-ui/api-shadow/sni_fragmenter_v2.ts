export class SniFragmenterV2 {
  public decoyDomain: string;
  constructor(decoyDomain: string = 'www.microsoft.com') {
    this.decoyDomain = decoyDomain;
  }

  splitInMiddle(data: Uint8Array): [Uint8Array, Uint8Array] {
    const mid = Math.floor(data.length / 2);
    return [data.slice(0, mid), data.slice(mid)];
  }

  injectDecoy(realClientHello: Uint8Array): [Uint8Array, Uint8Array] {
    const encoder = new TextEncoder();
    const domainBytes = encoder.encode(this.decoyDomain);
    const decoy = new Uint8Array(5 + domainBytes.length);
    decoy.set([0x16, 0x03, 0x01, 0x00, 0x10], 0);
    decoy.set(domainBytes, 5);
    return [decoy, realClientHello];
  }
}
