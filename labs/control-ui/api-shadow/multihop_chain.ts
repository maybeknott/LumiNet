export interface RelayHop {
  hopIndex: number;
  endpoint: string;
  publicKey: string;
}

export class MultihopRelayChain {
  public readonly entryHop: RelayHop;
  public readonly exitHop: RelayHop;
  public readonly quantumResistantPsk: Uint8Array;
  constructor(entryHop: RelayHop, exitHop: RelayHop, quantumResistantPsk: Uint8Array) {
    this.entryHop = entryHop;
    this.exitHop = exitHop;
    this.quantumResistantPsk = quantumResistantPsk;
  }

  public getNestedAllowedIps(): [string, string] {
    return ['10.64.0.1/32', '0.0.0.0/0, ::/0'];
  }
}
