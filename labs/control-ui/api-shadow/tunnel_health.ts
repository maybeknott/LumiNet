export type TunnelHealthVerdict =
  | "Disconnected"
  | "Starting"
  | "Working"
  | "Degraded"
  | "ReconnectNeeded"
  | "Broken"
  | "WaitingForTraffic";

export type EncryptionLevel = "Standard" | "Strong" | "Maximum";

export interface FecProfile {
  name: "None" | "Conservative" | "Balanced" | "Aggressive";
  lossTolerancePct: number;
  redundancyPct: number;
  flushTimeoutMs: number;
}

export const FEC_PROFILES: Record<FecProfile["name"], FecProfile> = {
  None: { name: "None", lossTolerancePct: 0, redundancyPct: 0, flushTimeoutMs: 0 },
  Conservative: { name: "Conservative", lossTolerancePct: 8, redundancyPct: 15, flushTimeoutMs: 25 },
  Balanced: { name: "Balanced", lossTolerancePct: 12, redundancyPct: 25, flushTimeoutMs: 20 },
  Aggressive: { name: "Aggressive", lossTolerancePct: 16, redundancyPct: 40, flushTimeoutMs: 15 },
};

export interface TunnelMetrics {
  packetsTx: number;
  packetsRx: number;
  bytesTx: number;
  bytesRx: number;
  latencyMs: number;
  lossRatio: number;
  consecutiveFailures: number;
  lastHandshakeAgeSec: number;
}

export class TunnelHealthEvaluator {
  public static evaluate(metrics: TunnelMetrics): TunnelHealthVerdict {
    if (metrics.packetsTx === 0 && metrics.packetsRx === 0 && metrics.lastHandshakeAgeSec === 0) {
      return "Disconnected";
    }
    if (metrics.packetsTx > 0 && metrics.packetsRx === 0 && metrics.lastHandshakeAgeSec < 10 && metrics.consecutiveFailures === 0) {
      return "Starting";
    }
    if (metrics.consecutiveFailures >= 5 || metrics.lastHandshakeAgeSec > 180) {
      return "Broken";
    }
    if (metrics.consecutiveFailures >= 3 || metrics.lastHandshakeAgeSec > 60 || metrics.lossRatio > 0.35) {
      return "ReconnectNeeded";
    }
    if (metrics.lossRatio > 0.10 || metrics.latencyMs > 350) {
      return "Degraded";
    }
    if (metrics.packetsTx > 0 && metrics.packetsRx === 0 && metrics.lastHandshakeAgeSec >= 10) {
      return "WaitingForTraffic";
    }
    return "Working";
  }

  public static recommendFec(lossRatio: number, isCellular: boolean): FecProfile {
    if (lossRatio > 0.15 || (isCellular && lossRatio > 0.08)) {
      return FEC_PROFILES.Aggressive;
    }
    if (lossRatio > 0.05 || isCellular) {
      return FEC_PROFILES.Balanced;
    }
    if (lossRatio > 0.01) {
      return FEC_PROFILES.Conservative;
    }
    return FEC_PROFILES.None;
  }

  public static stripSecrets(rawConfig: string): string {
    const patterns = [
      /(password\s*[:=]\s*)[^\r\n,;]+/gi,
      /(private_key\s*[:=]\s*)[^\r\n,;]+/gi,
      /(preshared_key\s*[:=]\s*)[^\r\n,;]+/gi,
      /(token\s*[:=]\s*)[^\r\n,;]+/gi,
      /(secret\s*[:=]\s*)[^\r\n,;]+/gi,
    ];
    let sanitized = rawConfig;
    for (const pattern of patterns) {
      sanitized = sanitized.replace(pattern, "$1[REDACTED]");
    }
    return sanitized;
  }
}
