export type UIEvasionMode = 'STANDARD' | 'SPLIT' | 'FAKE_TTL' | 'DISORDER';

export class AutonomousEvasionUI {
  private _mode: UIEvasionMode = 'STANDARD';
  private _rstCount = 0;
  public readonly rstThreshold;
  constructor(rstThreshold = 3) {
    this.rstThreshold = rstThreshold;
  }

  get mode(): UIEvasionMode {
    return this._mode;
  }

  recordTcpReset(): UIEvasionMode {
    this._rstCount++;
    if (this._rstCount >= this.rstThreshold) {
      if (this._mode === 'STANDARD') this._mode = 'SPLIT';
      else if (this._mode === 'SPLIT') this._mode = 'FAKE_TTL';
      else if (this._mode === 'FAKE_TTL') this._mode = 'DISORDER';
      else this._mode = 'STANDARD';
      this._rstCount = 0;
    }
    return this._mode;
  }

  reset(): void {
    this._mode = 'STANDARD';
    this._rstCount = 0;
  }
}
