export interface GeoCidrRecord {
  netAddr: number;
  mask: number;
  countryCode: string;
}

export class EnhancedGeoIpLookup {
  private entries: GeoCidrRecord[] = [];

  addCidr(ipStr: string, maskBits: number, countryCode: string): void {
    const ipLong = this.ipToLong(ipStr);
    if (ipLong === null) return;
    const mask = maskBits === 0 ? 0 : (~0 << (32 - maskBits)) >>> 0;
    this.entries.push({
      netAddr: (ipLong & mask) >>> 0,
      mask,
      countryCode: countryCode.trim().toUpperCase(),
    });
  }

  lookup(ipStr: string): string | undefined {
    const ipLong = this.ipToLong(ipStr);
    if (ipLong === null) return undefined;

    let bestMatch: string | undefined = undefined;
    let bestMask = -1;

    for (const e of this.entries) {
      if ((ipLong & e.mask) >>> 0 === e.netAddr) {
        if (e.mask > bestMask) {
          bestMatch = e.countryCode;
          bestMask = e.mask;
        }
      }
    }
    return bestMatch;
  }

  static isPrivate(ipStr: string): boolean {
    const parts = ipStr.split('.').map((p) => parseInt(p, 10));
    if (parts.length !== 4) return false;
    const [first, second] = parts as [number, number];

    if (first === 10 || first === 127) return true;
    if (first === 172 && second >= 16 && second <= 31) return true;
    if (first === 192 && second === 168) return true;
    return false;
  }

  private ipToLong(ip: string): number | null {
    const parts = ip.split('.').map((p) => parseInt(p, 10));
    if (parts.length !== 4 || parts.some((p) => isNaN(p) || p < 0 || p > 255)) {
      return null;
    }
    return ((parts[0]! << 24) | (parts[1]! << 16) | (parts[2]! << 8) | parts[3]!) >>> 0;
  }
}
