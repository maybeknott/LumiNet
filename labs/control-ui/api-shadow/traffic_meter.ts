export interface TrafficSample {
  receivedBytes: number;
  sentBytes: number;
  downloadBytesPerSec: number;
  uploadBytesPerSec: number;
  supported: boolean;
}

export type SplitTunnelMode = "ALL" | "ONLY" | "EXCEPT";

export interface SplitTunnelPolicy {
  mode: SplitTunnelMode;
  packages: string[];
}

export class SplitTunnelCoordinator {
  public static effectivePackages(policy: SplitTunnelPolicy, selfId: string): string[] {
    return policy.packages.filter((pkg) => pkg && pkg.trim() !== "" && pkg !== selfId);
  }

  public static isEffectivelyAll(policy: SplitTunnelPolicy, selfId: string): boolean {
    switch (policy.mode) {
      case "ALL":
        return true;
      case "ONLY":
        return false;
      case "EXCEPT":
        return this.effectivePackages(policy, selfId).length === 0;
      default:
        return true;
    }
  }

  public static validationError(policy: SplitTunnelPolicy, selfId: string): string | null {
    if (policy.mode === "ONLY" && this.effectivePackages(policy, selfId).length === 0) {
      return "Choose at least one app, or switch back to All apps";
    }
    return null;
  }
}

export class TrafficMeterRateSmoother {
  private smoothedDown = 0;
  private smoothedUp = 0;

  public smooth(rawDown: number, rawUp: number): { downloadRate: number; uploadRate: number } {
    this.smoothedDown = this.smoothedDown <= 0 ? rawDown : this.smoothedDown * 0.4 + rawDown * 0.6;
    this.smoothedUp = this.smoothedUp <= 0 ? rawUp : this.smoothedUp * 0.4 + rawUp * 0.6;
    return {
      downloadRate: Math.round(this.smoothedDown),
      uploadRate: Math.round(this.smoothedUp),
    };
  }

  public reset(): void {
    this.smoothedDown = 0;
    this.smoothedUp = 0;
  }
}

export function formatBytes(bytes: number): string {
  if (bytes < 1024) return `${bytes} B`;
  const units = ["KB", "MB", "GB", "TB"];
  let val = bytes / 1024;
  let unit = 0;
  while (val >= 1024 && unit < units.length - 1) {
    val /= 1024;
    unit++;
  }
  return val < 10 ? `${val.toFixed(1)} ${units[unit]}` : `${Math.round(val)} ${units[unit]}`;
}

export function formatRate(bytesPerSec: number): string {
  return `${formatBytes(bytesPerSec)}/s`;
}
