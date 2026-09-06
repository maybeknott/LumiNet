/**
 * Client Rate-Limiter and IP Ban Supervisor
 */
export type AccessDecision = 'Allowed' | 'Throttled' | 'Banned';

interface ClientRecord {
  failures: number;
  tokens: number;
  lastAccessUnix: number;
  bannedUntilUnix: number;
}

export class ClientBanSupervisor {
  private clients: Map<string, ClientRecord> = new Map();
  public maxFailures: number;
  public banDurationSecs: number;
  public bucketCapacity: number;
  public refillRatePerSec: number;
  constructor(
    maxFailures: number = 5,
    banDurationSecs: number = 300,
    bucketCapacity: number = 10.0,
    refillRatePerSec: number = 1.0,
  ) {
    this.maxFailures = maxFailures;
    this.banDurationSecs = banDurationSecs;
    this.bucketCapacity = bucketCapacity;
    this.refillRatePerSec = refillRatePerSec;
  }

  checkAccess(ip: string, nowUnix: number): { decision: AccessDecision; remainingSecs: number } {
    let rec = this.clients.get(ip);
    if (!rec) {
      rec = {
        failures: 0,
        tokens: this.bucketCapacity,
        lastAccessUnix: nowUnix,
        bannedUntilUnix: 0,
      };
      this.clients.set(ip, rec);
    }

    if (rec.bannedUntilUnix > nowUnix) {
      return {
        decision: 'Banned',
        remainingSecs: rec.bannedUntilUnix - nowUnix,
      };
    }

    const elapsed = Math.max(0, nowUnix - rec.lastAccessUnix);
    rec.tokens = Math.min(this.bucketCapacity, rec.tokens + elapsed * this.refillRatePerSec);
    rec.lastAccessUnix = nowUnix;

    if (rec.tokens < 1.0) {
      return { decision: 'Throttled', remainingSecs: 0 };
    }

    rec.tokens -= 1.0;
    return { decision: 'Allowed', remainingSecs: 0 };
  }

  recordAuthResult(ip: string, success: boolean, nowUnix: number): void {
    let rec = this.clients.get(ip);
    if (!rec) {
      rec = {
        failures: 0,
        tokens: this.bucketCapacity,
        lastAccessUnix: nowUnix,
        bannedUntilUnix: 0,
      };
      this.clients.set(ip, rec);
    }

    if (success) {
      rec.failures = 0;
    } else {
      rec.failures++;
      if (rec.failures >= this.maxFailures) {
        rec.bannedUntilUnix = nowUnix + this.banDurationSecs;
      }
    }
  }

  unban(ip: string): void {
    const rec = this.clients.get(ip);
    if (rec) {
      rec.bannedUntilUnix = 0;
      rec.failures = 0;
    }
  }

  isBanned(ip: string, nowUnix: number): boolean {
    return (this.clients.get(ip)?.bannedUntilUnix ?? 0) > nowUnix;
  }
}
