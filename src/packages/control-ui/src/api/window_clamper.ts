export class WindowClamper {
  public clampedSize: number;
  public enabled: boolean;
  constructor(clampedSize: number = 4, enabled: boolean = true) {
    this.clampedSize = clampedSize;
    this.enabled = enabled;
  }

  clampWindow(originalWindow: number, isHandshake: boolean): number {
    if (!this.enabled) return originalWindow;
    return isHandshake && originalWindow > this.clampedSize ? this.clampedSize : originalWindow;
  }

  isRstLegitimate(rstSeq: number, lastAckSeq: number, window: number): boolean {
    const diff = rstSeq - lastAckSeq;
    const maxWin = Math.max(window, 4096);
    return diff >= 0 && diff <= maxWin;
  }
}
