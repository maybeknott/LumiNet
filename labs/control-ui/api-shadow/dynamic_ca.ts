export interface GeneratedCert {
  commonName: string;
  serialNumber: number;
  notBeforeMs: number;
  notAfterMs: number;
  certPayload: Uint8Array;
}

export class DynamicCaManager {
  private serialCounter = 1000;
  private readonly cache = new Map<string, GeneratedCert>();
  private readonly caName;
  constructor(caName = 'LumiNet Root CA') {
    this.caName = caName;
  }

  public issueOrGetCert(
    commonName: string,
    validityDurationMs: number,
    nowMs = Date.now(),
  ): GeneratedCert {
    const existing = this.cache.get(commonName);
    if (existing && nowMs < existing.notAfterMs) {
      return existing;
    }

    this.serialCounter++;
    const enc = new TextEncoder();
    const payload = enc.encode(`MOCK-CERT:${this.caName}:${commonName}:${this.serialCounter}`);
    const cert: GeneratedCert = {
      commonName,
      serialNumber: this.serialCounter,
      notBeforeMs: nowMs,
      notAfterMs: nowMs + validityDurationMs,
      certPayload: payload,
    };
    this.cache.set(commonName, cert);
    return cert;
  }
}
