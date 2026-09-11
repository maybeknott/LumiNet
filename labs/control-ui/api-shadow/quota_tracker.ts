/**
 * Quota and rate-limit tracking for proxy endpoints and relay workers.
 */

export interface AccountBucketState {
  maskedId: string;
  requestsUsed: number;
  failedRequests: number;
  bytesTotal: number;
  nextResetAt: number;
  exhausted: boolean;
  quarantined: boolean;
}

/**
 * Token bucket rate limiter.
 */
export class TokenBucketLimiter {
  public readonly rate: number;
  public readonly capacity: number;
  private tokens: number;
  private lastRefillMs: number;

  constructor(rate: number, capacity: number) {
    this.rate = rate;
    this.capacity = capacity;
    this.tokens = capacity;
    this.lastRefillMs = Date.now();
  }

  public allow(): boolean {
    return this.take(1);
  }

  public take(n: number): boolean {
    const now = Date.now();
    const elapsedSec = (now - this.lastRefillMs) / 1000;
    this.lastRefillMs = now;

    this.tokens = Math.min(this.capacity, this.tokens + elapsedSec * this.rate);

    if (this.tokens >= n) {
      this.tokens -= n;
      return true;
    }
    return false;
  }
}

/**
 * Multi-account quota manager with rolling window reset.
 */
export class MultiQuotaTracker {
  private readonly windowDurationSec: number;
  private readonly requestLimit: number;
  private readonly buckets: Map<string, AccountBucketState> = new Map();

  constructor(windowDurationSec: number = 86400, requestLimit: number = 20000) {
    this.windowDurationSec = windowDurationSec;
    this.requestLimit = requestLimit;
  }

  public register(id: string): void {
    if (!this.buckets.has(id)) {
      const masked = id.length <= 8 ? id : `${id.slice(0, 4)}...${id.slice(-4)}`;
      this.buckets.set(id, {
        maskedId: masked,
        requestsUsed: 0,
        failedRequests: 0,
        bytesTotal: 0,
        nextResetAt: 0,
        exhausted: false,
        quarantined: false,
      });
    }
  }

  public recordOutcome(
    id: string,
    nowUnix: number,
    upBytes: number,
    downBytes: number,
    success: boolean
  ): void {
    let b = this.buckets.get(id);
    if (!b) {
      this.register(id);
      b = this.buckets.get(id)!;
    }

    if (b.nextResetAt > 0 && nowUnix >= b.nextResetAt) {
      b.requestsUsed = 0;
      b.failedRequests = 0;
      b.bytesTotal = 0;
      b.nextResetAt = 0;
      b.exhausted = false;
      b.quarantined = false;
    }

    if (b.nextResetAt === 0) {
      b.nextResetAt = nowUnix + this.windowDurationSec;
    }

    b.requestsUsed++;
    b.bytesTotal += (upBytes + downBytes);

    if (!success) {
      b.failedRequests++;
      if (b.failedRequests >= 5) {
        b.quarantined = true;
      }
    }

    if (b.requestsUsed >= this.requestLimit) {
      b.exhausted = true;
    }
  }

  public selectBestAccount(nowUnix: number): string | null {
    let bestId: string | null = null;
    let lowestUsage = Infinity;

    for (const [id, b] of this.buckets.entries()) {
      if (b.nextResetAt > 0 && nowUnix >= b.nextResetAt) {
        b.requestsUsed = 0;
        b.failedRequests = 0;
        b.bytesTotal = 0;
        b.nextResetAt = 0;
        b.exhausted = false;
        b.quarantined = false;
      }

      if (b.exhausted || b.quarantined) {
        continue;
      }

      if (b.requestsUsed < lowestUsage) {
        lowestUsage = b.requestsUsed;
        bestId = id;
      }
    }

    return bestId;
  }
}
