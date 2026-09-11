export const QuotaAlertLevel = {
  Normal: 'normal',
  Warning80: 'warning_80',
  Exhausted: 'exhausted',
} as const;
export type QuotaAlertLevel = (typeof QuotaAlertLevel)[keyof typeof QuotaAlertLevel];

export interface UserBandwidthQuota {
  userId: string;
  maxBytes: number;
  usedBytes: number;
  isActive: boolean;
}

export class BandwidthQuotaEnforcer {
  private readonly quotas = new Map<string, UserBandwidthQuota>();

  public registerUser(userId: string, maxBytes: number): void {
    this.quotas.set(userId, {
      userId,
      maxBytes,
      usedBytes: 0,
      isActive: true,
    });
  }

  public recordTraffic(userId: string, bytes: number): QuotaAlertLevel {
    const q = this.quotas.get(userId);
    if (!q) return QuotaAlertLevel.Exhausted;
    q.usedBytes += bytes;
    if (q.usedBytes >= q.maxBytes) {
      q.isActive = false;
      return QuotaAlertLevel.Exhausted;
    }
    if (q.usedBytes >= (q.maxBytes * 8) / 10) {
      return QuotaAlertLevel.Warning80;
    }
    return QuotaAlertLevel.Normal;
  }

  public isUserAllowed(userId: string): boolean {
    return this.quotas.get(userId)?.isActive ?? false;
  }
}
