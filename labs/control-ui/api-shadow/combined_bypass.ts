/**
 * Combined Multi-Layer DPI Bypass & Domain Evasion Evaluator API
 * Originates from SNISPF-main and adapted for LumiNet unified network plane.
 */

export type BypassMode =
  'Direct' | 'FakeSniDecoy' | 'SniFragment' | 'CombinedTtlDecoy' | 'CombinedRawDesync';

export interface CombinedBypassConfig {
  mode: BypassMode;
  fake_sni: string;
  use_ttl_trick: boolean;
  ttl_hops: number;
  fragment_strategy: 'sni_split' | 'sni_boundary' | 'half' | 'tls_record';
  fragment_delay_ms: number;
}

export const DEFAULT_COMBINED_BYPASS_CONFIG: CombinedBypassConfig = {
  mode: 'CombinedTtlDecoy',
  fake_sni: 'auth.vercel.com',
  use_ttl_trick: true,
  ttl_hops: 2,
  fragment_strategy: 'sni_split',
  fragment_delay_ms: 10,
};

export interface DecoyProbeSpec {
  ttl: number;
  payload: Uint8Array;
}

export interface FragmentSpec {
  payload: Uint8Array;
  delay_ms: number;
}

export interface PreparedEvasionPlan {
  decoy_probe?: DecoyProbeSpec | undefined;
  fragments: FragmentSpec[];
}

export interface DomainEvaluationResult {
  domain: string;
  mode: BypassMode;
  success: boolean;
  latency_ms: number;
  http_status?: number;
  error?: string;
  tested_at?: number;
}

/**
 * Plans the combined evasion sequence with optional decoy probe and fragments.
 */
export function planCombinedEvasion(
  realHello: Uint8Array,
  fakeHello: Uint8Array,
  config: CombinedBypassConfig = DEFAULT_COMBINED_BYPASS_CONFIG,
): PreparedEvasionPlan {
  const decoy_probe =
    config.use_ttl_trick || config.mode === 'CombinedTtlDecoy'
      ? {
          ttl: config.ttl_hops > 0 ? config.ttl_hops : 2,
          payload: new Uint8Array(fakeHello),
        }
      : undefined;

  const fragments: FragmentSpec[] = [];
  if (realHello.length === 0) {
    return { decoy_probe, fragments };
  }

  let splitPos = Math.floor(realHello.length / 2);
  if (splitPos === 0) splitPos = 1;

  if (config.fragment_strategy === 'sni_split' && realHello.length > 50) {
    splitPos = 43;
  }

  if (realHello.length > 1 && splitPos < realHello.length) {
    fragments.push({
      payload: realHello.slice(0, splitPos),
      delay_ms: 0,
    });
    fragments.push({
      payload: realHello.slice(splitPos),
      delay_ms: config.fragment_delay_ms,
    });
  } else {
    fragments.push({
      payload: realHello.slice(),
      delay_ms: 0,
    });
  }

  return { decoy_probe, fragments };
}

/**
 * Evaluates domain test results and selects the optimal bypass mode based on priority hierarchy:
 * Direct -> SniFragment -> FakeSniDecoy -> CombinedTtlDecoy -> CombinedRawDesync
 */
export function selectOptimalMode(results: DomainEvaluationResult[]): BypassMode | null {
  const hierarchy: BypassMode[] = [
    'Direct',
    'SniFragment',
    'FakeSniDecoy',
    'CombinedTtlDecoy',
    'CombinedRawDesync',
  ];

  for (const mode of hierarchy) {
    if (results.some((r) => r.mode === mode && r.success)) {
      return mode;
    }
  }

  return null;
}
