export type ManagedAccountStatus = 'READY' | 'IN_USE' | 'COOLING_DOWN' | 'LOCKED';

export interface ManagedAccountEntry {
  accountId: string;
  token: string;
  usesCount: number;
  maxUses: number;
  status: ManagedAccountStatus;
  cooldownUntilSec: number;
}

export class SessionRotationPool {
  private accounts = new Map<string, ManagedAccountEntry>();
  private rotationOrder: string[] = [];
  private cursor = 0;
  private defaultCooldownSec: number;
  constructor(defaultCooldownSec: number = 60) {
    this.defaultCooldownSec = defaultCooldownSec;
  }

  addAccount(accountId: string, token: string, maxUses: number): void {
    this.accounts.set(accountId, {
      accountId,
      token,
      usesCount: 0,
      maxUses,
      status: 'READY',
      cooldownUntilSec: 0,
    });
    this.rotationOrder.push(accountId);
  }

  acquireAccount(nowSec: number): { accountId: string; token: string } | null {
    if (this.rotationOrder.length === 0) return null;

    for (const acc of this.accounts.values()) {
      if (acc.status === 'COOLING_DOWN' && nowSec >= acc.cooldownUntilSec) {
        acc.status = 'READY';
        acc.usesCount = 0;
      }
    }

    const n = this.rotationOrder.length;
    for (let i = 0; i < n; i++) {
      const id = this.rotationOrder[this.cursor % n];
      this.cursor++;

      const acc = this.accounts.get(id!);
      if (acc && acc.status === 'READY') {
        acc.usesCount++;
        if (acc.usesCount >= acc.maxUses) {
          acc.status = 'COOLING_DOWN';
          acc.cooldownUntilSec = nowSec + this.defaultCooldownSec;
        }
        return { accountId: acc.accountId, token: acc.token };
      }
    }
    return null;
  }

  markLocked(accountId: string): void {
    const acc = this.accounts.get(accountId);
    if (acc) {
      acc.status = 'LOCKED';
    }
  }

  availableCount(nowSec: number): number {
    let count = 0;
    for (const acc of this.accounts.values()) {
      if (
        acc.status === 'READY' ||
        (acc.status === 'COOLING_DOWN' && nowSec >= acc.cooldownUntilSec)
      ) {
        count++;
      }
    }
    return count;
  }
}
