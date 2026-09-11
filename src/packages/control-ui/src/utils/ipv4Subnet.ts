// SPDX-License-Identifier: MIT
//
// Cleanroom implementation of IPv4 subnet calculations and target walking.
// Ported and unified from donor DnsScannerEngine.kt.

export interface Ipv4Range {
  start: number;
  end: number;
}

export class Ipv4Prefix {
  readonly baseAddress: number;
  readonly prefixLength: number;
  readonly maskedBaseAddress: number;

  constructor(baseAddress: number, prefixLength: number) {
    if (prefixLength < 0 || prefixLength > 32) {
      throw new Error(`prefixLength must be between 0 and 32, got ${prefixLength}`);
    }
    this.baseAddress = baseAddress >>> 0;
    this.prefixLength = prefixLength;
    this.maskedBaseAddress = Ipv4Math.maskAddress(this.baseAddress, prefixLength);
  }

  normalizedString(): string {
    return `${Ipv4Math.formatAddress(this.maskedBaseAddress)}/${this.prefixLength}`;
  }

  addressCount(): number {
    return 2 ** (32 - this.prefixLength);
  }

  usableHostCount(): number {
    const total = this.addressCount();
    return this.prefixLength < 31 && total >= 2 ? total - 2 : total;
  }

  hostBounds(): Ipv4Range | null {
    const total = this.addressCount();
    if (total <= 0) return null;

    const start =
      this.prefixLength < 31 && total >= 2
        ? (this.maskedBaseAddress + 1) >>> 0
        : this.maskedBaseAddress;
    const end =
      this.prefixLength < 31 && total >= 2
        ? (this.maskedBaseAddress + total - 2) >>> 0
        : (this.maskedBaseAddress + total - 1) >>> 0;

    return { start, end };
  }
}

export const Ipv4Math = {
  parseTarget(raw: string): Ipv4Prefix {
    const trimmed = raw.trim();
    return trimmed.includes('/')
      ? Ipv4Math.parsePrefix(trimmed)
      : new Ipv4Prefix(Ipv4Math.parseAddress(trimmed), 32);
  },

  parsePrefix(raw: string): Ipv4Prefix {
    const parts = raw.split('/');
    if (parts.length !== 2) {
      throw new Error(`invalid target "${raw}"`);
    }
    const address = Ipv4Math.parseAddress(parts[0]!.trim());
    const prefixLength = Number.parseInt(parts[1]!.trim(), 10);
    if (Number.isNaN(prefixLength) || prefixLength < 0 || prefixLength > 32) {
      throw new Error(`invalid target "${raw}"`);
    }
    return new Ipv4Prefix(address, prefixLength);
  },

  parseAddress(raw: string): number {
    const octets = raw.split('.');
    if (octets.length !== 4) {
      throw new Error(`invalid target "${raw}"`);
    }

    let value = 0;
    for (const octet of octets) {
      if (!octet.trim()) {
        throw new Error(`invalid target "${raw}"`);
      }
      const parsed = Number.parseInt(octet, 10);
      if (Number.isNaN(parsed) || parsed < 0 || parsed > 255) {
        throw new Error(`invalid target "${raw}"`);
      }
      value = ((value << 8) | parsed) >>> 0;
    }
    return value;
  },

  formatAddress(raw: number): string {
    const u = raw >>> 0;
    return `${(u >>> 24) & 0xff}.${(u >>> 16) & 0xff}.${(u >>> 8) & 0xff}.${u & 0xff}`;
  },

  maskAddress(raw: number, prefixLength: number): number {
    if (prefixLength === 0) return 0;
    const shift = 32 - prefixLength;
    const mask = ((0xffffffff >>> shift) << shift) >>> 0;
    return (raw & mask) >>> 0;
  },
};

export class HostWalker {
  walk(
    prefixes: string[],
    limit: number = Number.MAX_SAFE_INTEGER,
    onHost: (address: string, prefix: string) => boolean | void,
  ): number {
    let emitted = 0;

    for (const prefixStr of prefixes) {
      let prefix: Ipv4Prefix;
      try {
        prefix = Ipv4Math.parsePrefix(prefixStr);
      } catch {
        continue;
      }

      const bounds = prefix.hostBounds();
      if (!bounds) continue;

      for (let addr = bounds.start; addr <= bounds.end; addr++) {
        if (emitted >= limit) {
          return emitted;
        }
        const ipStr = Ipv4Math.formatAddress(addr);
        const shouldContinue = onHost(ipStr, prefixStr);
        emitted++;

        if (shouldContinue === false) {
          return emitted;
        }
      }
    }

    return emitted;
  }
}
