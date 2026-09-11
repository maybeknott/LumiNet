// Control UI TypeScript: Tor Pluggable Transport Stealth Bridge Collector API

export type PluggableTransportType = 'obfs4' | 'snowflake' | 'webtunnel' | 'meek' | 'custom';

export interface StealthBridge {
  transport: PluggableTransportType;
  endpoint: string;
  fingerprint: string;
  params: Record<string, string>;
  score: number;
  latencyMs: number;
  verified: boolean;
}

export class StealthBridgeCollector {
  public minScoreThreshold: number;
  public bridges: Map<string, StealthBridge> = new Map();

  constructor(minScoreThreshold: number = 0.5) {
    this.minScoreThreshold = minScoreThreshold;
  }

  public parseBridgeLine(line: string): StealthBridge {
    const trimmed = line.trim();
    if (!trimmed || trimmed.startsWith('#')) {
      throw new Error('Empty or comment line');
    }

    const parts = trimmed.split(/\s+/);
    if (parts.length < 3) throw new Error('Insufficient tokens in bridge line');

    const proto = parts[0]!.toLowerCase();
    const transport: PluggableTransportType =
      proto === 'obfs4' || proto === 'snowflake' || proto === 'webtunnel' || proto === 'meek'
        ? (proto as PluggableTransportType)
        : 'custom';

    const endpoint = parts[1];
    const fingerprint = parts[2]!.toUpperCase();

    const params: Record<string, string> = {};
    for (const token of parts.slice(3)) {
      const idx = token.indexOf('=');
      if (idx !== -1) {
        params[token.slice(0, idx)] = token.slice(idx + 1);
      }
    }

    const bridge: StealthBridge = {
      transport,
      endpoint: endpoint!,
      fingerprint,
      params,
      score: 1.0,
      latencyMs: 0,
      verified: false,
    };

    this.bridges.set(fingerprint, bridge);
    return bridge;
  }

  public recordHealth(fingerprint: string, latencyMs: number, success: boolean): boolean {
    const bridge = this.bridges.get(fingerprint.toUpperCase());
    if (!bridge) return false;

    if (success) {
      bridge.verified = true;
      bridge.latencyMs = latencyMs;
      const factor = Math.min(2.0, 1000.0 / Math.max(50, latencyMs));
      bridge.score = bridge.score * 0.8 + 1.2 * factor;
    } else {
      bridge.score *= 0.5;
      if (bridge.score < 0.1) bridge.verified = false;
    }
    return true;
  }

  public getBestBridges(transport?: PluggableTransportType, limit: number = 5): StealthBridge[] {
    return Array.from(this.bridges.values())
      .filter((b) => (!transport || b.transport === transport) && b.score >= this.minScoreThreshold)
      .sort((a, b) => b.score - a.score)
      .slice(0, limit);
  }
}
