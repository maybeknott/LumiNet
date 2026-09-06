export class BrutalPacer {
  public targetBps: number;
  public readonly minBps: number;
  public readonly maxBps: number;
  constructor(targetBps: number, minBps: number = 1000000, maxBps: number = 100000000) {
    this.targetBps = targetBps;
    this.minBps = minBps;
    this.maxBps = maxBps;
  }

  public updateAckFeedback(ackRateBps: number, lossRatio: number): number {
    const boundedLoss = Math.max(0.0, Math.min(1.0, lossRatio));
    // R = AckRate * (1 + loss)
    const compensation = ackRateBps * (1.0 + boundedLoss);
    this.targetBps = Math.max(this.minBps, Math.min(this.maxBps, Math.round(compensation)));
    return this.targetBps;
  }

  public getPacingDelayMs(packetBytes: number): number {
    if (this.targetBps <= 0) return 0;
    return (packetBytes * 8 * 1000) / this.targetBps;
  }
}

export class SalamanderObfuscator {
  private pos = 0;
  private readonly key: Uint8Array;
  constructor(key: Uint8Array) {
    this.key = key;
  }

  public applyInPlace(data: Uint8Array): void {
    const kLen = this.key.length;
    for (let i = 0; i < data.length; i++) {
      const k = this.key[this.pos % kLen] ?? 0;
      data[i] = (data[i] ?? 0) ^ k;
      this.pos++;
    }
  }
}
