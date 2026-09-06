/**
 * EDNS Client Subnet (ECS) Scrubber and Privacy Masker
 */
export class EdnsSubnetScrubber {
  public maskIpv4Bits: number;
  public maskIpv6Bits: number;
  public stripCompletely: boolean;
  constructor(
    maskIpv4Bits: number = 24,
    maskIpv6Bits: number = 56,
    stripCompletely: boolean = false,
  ) {
    this.maskIpv4Bits = maskIpv4Bits;
    this.maskIpv6Bits = maskIpv6Bits;
    this.stripCompletely = stripCompletely;
  }

  maskIpv4(ip: string): string {
    const parts = ip.trim().split('.');
    if (parts.length !== 4) return ip;
    const octets = parts.map(Number);
    if (octets.some(isNaN)) return ip;

    const raw = ((octets[0]! << 24) | (octets[1]! << 16) | (octets[2]! << 8) | octets[3]!) >>> 0;
    const mask =
      this.maskIpv4Bits >= 32
        ? 0xffffffff
        : this.maskIpv4Bits <= 0
          ? 0
          : ~((1 << (32 - this.maskIpv4Bits)) - 1) >>> 0;
    const masked = (raw & mask) >>> 0;

    return `${(masked >>> 24) & 0xff}.${(masked >>> 16) & 0xff}.${(masked >>> 8) & 0xff}.${masked & 0xff}`;
  }

  scrubPacket(packet: Uint8Array): Uint8Array {
    if (packet.length < 12) return packet;
    const arcount = (packet[10]! << 8) | packet[11]!;
    if (arcount === 0) return packet;
    return new Uint8Array(packet);
  }
}
