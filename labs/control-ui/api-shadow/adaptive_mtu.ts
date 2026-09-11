/**
 * Adaptive Path MTU Discovery
 */
export class AdaptiveMtuDiscovery {
  public currentProbe: number;
  public convergedMtu: number | null = null;
  private minMtu: number;
  private maxMtu: number;
  constructor(minMtu: number = 1280, maxMtu: number = 1500) {
    this.minMtu = minMtu;
    this.maxMtu = maxMtu;
    this.currentProbe = Math.floor((minMtu + maxMtu) / 2);
  }

  nextProbeSize(): number {
    return this.currentProbe;
  }

  recordResult(size: number, success: boolean): void {
    if (success) {
      this.minMtu = size;
    } else {
      this.maxMtu = Math.max(this.minMtu, size - 1);
    }

    if (this.minMtu >= this.maxMtu) {
      this.convergedMtu = this.minMtu;
    } else {
      this.currentProbe = Math.floor((this.minMtu + this.maxMtu + 1) / 2);
    }
  }

  optimalMtu(): number {
    return this.convergedMtu ?? this.minMtu;
  }

  wireguardPayloadMtu(isIpv6: boolean): number {
    const overhead = isIpv6 ? 80 : 60;
    return Math.max(1280, this.optimalMtu() - overhead);
  }

  optimalKeepaliveSecs(): number {
    return this.optimalMtu() < 1360 ? 15 : 25;
  }
}
