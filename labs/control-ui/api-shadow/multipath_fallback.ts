export const FallbackTierType = {
  Direct: 'direct',
  DomainFronted: 'domain_fronted',
  EncryptedTunnel: 'encrypted_tunnel',
  QuicFallback: 'quic_fallback',
} as const;
export type FallbackTierType = (typeof FallbackTierType)[keyof typeof FallbackTierType];

export interface FallbackTier {
  type: FallbackTierType;
  consecutiveFailures: number;
  maxFailures: number;
}

export class MultipathFallbackRouter {
  private readonly tiers: FallbackTier[] = [
    { type: FallbackTierType.Direct, consecutiveFailures: 0, maxFailures: 2 },
    {
      type: FallbackTierType.DomainFronted,
      consecutiveFailures: 0,
      maxFailures: 3,
    },
    {
      type: FallbackTierType.EncryptedTunnel,
      consecutiveFailures: 0,
      maxFailures: 3,
    },
    {
      type: FallbackTierType.QuicFallback,
      consecutiveFailures: 0,
      maxFailures: 5,
    },
  ];

  public selectActiveTier(): FallbackTierType | null {
    const tier = this.tiers.find((t) => t.consecutiveFailures < t.maxFailures);
    return tier ? tier.type : null;
  }

  public recordSuccess(type: FallbackTierType): void {
    const tier = this.tiers.find((t) => t.type === type);
    if (tier) tier.consecutiveFailures = 0;
  }

  public recordFailure(type: FallbackTierType): void {
    const tier = this.tiers.find((t) => t.type === type);
    if (tier) tier.consecutiveFailures++;
  }

  public resetCircuitBreakers(): void {
    for (const t of this.tiers) {
      t.consecutiveFailures = 0;
    }
  }
}
