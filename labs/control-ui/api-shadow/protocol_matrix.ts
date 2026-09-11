export interface ProtocolProfile {
  name: string;
  capabilities: Set<string>;
  score: number;
}

export class ProtocolCapabilityMatrix {
  public profiles: ProtocolProfile[] = [
    {
      name: 'Hysteria2',
      capabilities: new Set(['multipath_udp', 'padding', 'tls_spoof']),
      score: 95,
    },
    {
      name: 'VLESS-Reality',
      capabilities: new Set(['tls_spoof', 'replay_defense', 'padding']),
      score: 92,
    },
    {
      name: 'Trojan-SNI-Fragment',
      capabilities: new Set(['sni_fragmentation', 'tls_spoof']),
      score: 88,
    },
  ];

  recommend(required: string[]): ProtocolProfile | null {
    const candidates = this.profiles.filter((p) =>
      required.every((req) => p.capabilities.has(req)),
    );
    if (candidates.length === 0) return null;
    return candidates.sort((a, b) => b.score - a.score)[0]!;
  }
}
