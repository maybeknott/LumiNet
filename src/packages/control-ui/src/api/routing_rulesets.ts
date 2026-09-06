/**
 * Routing Rulesets & Multi-Hop Chain Configuration API.
 */

export type DomainStrategy = 'AsIs' | 'IPIfNonMatch' | 'IPOnDemand';

export type RoutingRulesetPreset =
  'Global' | 'BypassIran' | 'BypassRussia' | 'BypassChina' | 'BlockAds';

export interface RoutingRule {
  type: string;
  domain?: string[];
  ip?: string[];
  port?: string;
  inboundTag?: string[];
  outboundTag: string;
}

/**
 * Returns pre-compiled rule definitions for regional presets and ad blocking.
 */
export function getPresetRoutingRules(preset: RoutingRulesetPreset): RoutingRule[] {
  switch (preset) {
    case 'BlockAds':
      return [
        {
          type: 'field',
          domain: ['geosite:category-ads-all'],
          outboundTag: 'block',
        },
      ];
    case 'BypassIran':
      return [
        {
          type: 'field',
          domain: ['geosite:ir', 'domain:.ir'],
          ip: ['geoip:ir', 'geoip:private'],
          outboundTag: 'direct',
        },
      ];
    case 'BypassRussia':
      return [
        {
          type: 'field',
          domain: ['geosite:ru', 'domain:.ru'],
          ip: ['geoip:ru', 'geoip:private'],
          outboundTag: 'direct',
        },
      ];
    case 'BypassChina':
      return [
        {
          type: 'field',
          domain: ['geosite:cn', 'domain:.cn'],
          ip: ['geoip:cn', 'geoip:private'],
          outboundTag: 'direct',
        },
      ];
    case 'Global':
      return [
        {
          type: 'field',
          ip: ['geoip:private'],
          outboundTag: 'direct',
        },
      ];
  }
}

/**
 * Compiles a list of profile remarks into a multi-hop proxy chain definition.
 */
export function compileMultiHopChain(
  chainRemarks: string[],
  exitNodeRemark: string,
): { tag: string; dialerProxy?: string | undefined }[] {
  const allHops = [...chainRemarks, exitNodeRemark];
  return allHops.map((hopRemark: string, index: number) => {
    const isExit = index === allHops.length - 1;
    return {
      tag: hopRemark,
      dialerProxy: isExit ? undefined : allHops[index + 1],
    };
  });
}

/**
 * Retrieves the current routing strategy from the daemon.
 */
export async function fetchRoutingStrategy(): Promise<DomainStrategy> {
  const res = await fetch('/api/v1/routing/strategy');
  if (!res.ok) {
    return 'IPIfNonMatch';
  }
  const data = await res.json();
  return data.strategy || 'IPIfNonMatch';
}

/**
 * Updates the routing domain strategy in the running proxy core.
 */
export async function updateRoutingStrategy(strategy: DomainStrategy): Promise<void> {
  const res = await fetch('/api/v1/routing/strategy', {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({ strategy }),
  });
  if (!res.ok) {
    throw new Error(`Failed to update routing strategy: ${res.statusText}`);
  }
}
