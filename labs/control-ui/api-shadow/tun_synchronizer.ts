/**
 * TUN Routing and MSS Clamp Synchronizer
 */
export class TunRouteSynchronizer {
  private bypassPrefixes: string[] = [
    '10.',
    '127.',
    '169.254.',
    '172.16.',
    '192.168.',
    '224.',
    'fe80:',
    '::1',
  ];
  public tunMtu: number;
  constructor(tunMtu: number = 1400) {
    this.tunMtu = tunMtu;
  }

  addBypassPrefix(prefix: string): void {
    if (!this.bypassPrefixes.includes(prefix)) {
      this.bypassPrefixes.push(prefix);
    }
  }

  shouldBypass(ip: string): boolean {
    const trimmed = ip.trim();
    return this.bypassPrefixes.some((p) => trimmed.startsWith(p));
  }

  calculateClampedMss(isIpv6: boolean): number {
    const overhead = isIpv6 ? 60 : 40;
    return Math.max(1200, this.tunMtu - overhead);
  }
}
