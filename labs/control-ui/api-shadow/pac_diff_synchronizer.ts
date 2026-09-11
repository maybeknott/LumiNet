// Standard pure TypeScript SHA-256 implementation
function sha256Sync(data: string): string {
  function rightRotate(value: number, amount: number): number {
    return (value >>> amount) | (value << (32 - amount));
  }

  const mathPow = Math.pow;
  const maxWord = mathPow(2, 32);
  let result = '';

  const words: number[] = [];
  const asciiBitLength = data.length * 8;

  const hash: number[] = [];
  const k: number[] = [];
  let primeCounter = 0;

  const isPrime = (candidate: number) => {
    for (let factor = 2, max = Math.sqrt(candidate); factor <= max; factor++) {
      if (candidate % factor === 0) return false;
    }
    return true;
  };

  for (let candidate = 2; primeCounter < 64; candidate++) {
    if (isPrime(candidate)) {
      if (primeCounter < 8) {
        hash[primeCounter] = (mathPow(candidate, 1 / 2) * maxWord) | 0;
      }
      k[primeCounter] = (mathPow(candidate, 1 / 3) * maxWord) | 0;
      primeCounter++;
    }
  }

  for (let i = 0; i < data.length; i++) {
    const j = i >> 2;
    words[j] = (words[j] || 0) | ((data.charCodeAt(i) & 0xff) << ((3 - (i % 4)) * 8));
  }

  words[asciiBitLength >> 5] =
    (words[asciiBitLength >> 5] || 0) | (0x80 << (24 - (asciiBitLength % 32)));
  words[(((asciiBitLength + 64) >> 9) << 4) + 15] = asciiBitLength;

  for (let j = 0; j < words.length; j += 16) {
    const w: number[] = words.slice(j, j + 16);
    for (let i = 0; i < 16; i++) {
      w[i] = w[i] || 0;
    }

    for (let i = 16; i < 64; i++) {
      const w15 = w[i - 15] || 0;
      const w2 = w[i - 2] || 0;
      const s0 = rightRotate(w15, 7) ^ rightRotate(w15, 18) ^ (w15 >>> 3);
      const s1 = rightRotate(w2, 17) ^ rightRotate(w2, 19) ^ (w2 >>> 10);
      w[i] = ((w[i - 16] || 0) + s0 + (w[i - 7] || 0) + s1) | 0;
    }

    let a = hash[0] || 0;
    let b = hash[1] || 0;
    let c = hash[2] || 0;
    let d = hash[3] || 0;
    let e = hash[4] || 0;
    let f = hash[5] || 0;
    let g = hash[6] || 0;
    let h = hash[7] || 0;

    for (let i = 0; i < 64; i++) {
      const s1 = rightRotate(e, 6) ^ rightRotate(e, 11) ^ rightRotate(e, 25);
      const ch = (e & f) ^ (~e & g);
      const temp1 = (h + s1 + ch + (k[i] || 0) + (w[i] || 0)) | 0;
      const s0 = rightRotate(a, 2) ^ rightRotate(a, 13) ^ rightRotate(a, 22);
      const maj = (a & b) ^ (a & c) ^ (b & c);
      const temp2 = (s0 + maj) | 0;

      h = g;
      g = f;
      f = e;
      e = (d + temp1) | 0;
      d = c;
      c = b;
      b = a;
      a = (temp1 + temp2) | 0;
    }

    hash[0] = ((hash[0] || 0) + a) | 0;
    hash[1] = ((hash[1] || 0) + b) | 0;
    hash[2] = ((hash[2] || 0) + c) | 0;
    hash[3] = ((hash[3] || 0) + d) | 0;
    hash[4] = ((hash[4] || 0) + e) | 0;
    hash[5] = ((hash[5] || 0) + f) | 0;
    hash[6] = ((hash[6] || 0) + g) | 0;
    hash[7] = ((hash[7] || 0) + h) | 0;
  }

  for (let i = 0; i < 8; i++) {
    for (let j = 3; j >= 0; j--) {
      const byte = ((hash[i] || 0) >> (j * 8)) & 0xff;
      result += (byte < 16 ? '0' : '') + byte.toString(16);
    }
  }

  return result;
}

export interface PacSyncDelta {
  addedDomains: string[];
  removedDomains: string[];
  previousChecksum: string;
  newChecksum: string;
}

export class PacDiffSynchronizer {
  private activeRules: Set<string> = new Set();

  constructor(initialRules: string[] = []) {
    for (const r of initialRules) {
      const trimmed = r.trim().toLowerCase();
      if (trimmed.length > 0) {
        this.activeRules.add(trimmed);
      }
    }
  }

  computeDelta(upstreamRules: string[]): PacSyncDelta {
    const upstreamSet = new Set<string>();
    for (const r of upstreamRules) {
      const trimmed = r.trim().toLowerCase();
      if (trimmed.length > 0) {
        upstreamSet.add(trimmed);
      }
    }

    const added: string[] = [];
    for (const u of upstreamSet) {
      if (!this.activeRules.has(u)) {
        added.push(u);
      }
    }
    added.sort();

    const removed: string[] = [];
    for (const a of this.activeRules) {
      if (!upstreamSet.has(a)) {
        removed.push(a);
      }
    }
    removed.sort();

    const prevCk = this.currentChecksum();
    const newCk = PacDiffSynchronizer.computeChecksumForSet(upstreamSet);

    return {
      addedDomains: added,
      removedDomains: removed,
      previousChecksum: prevCk,
      newChecksum: newCk,
    };
  }

  applyDelta(delta: PacSyncDelta): number {
    const curCk = this.currentChecksum();
    if (curCk !== delta.previousChecksum) {
      throw new Error('Checksum mismatch: concurrent modification detected');
    }

    for (const rem of delta.removedDomains) {
      this.activeRules.delete(rem);
    }

    for (const add of delta.addedDomains) {
      this.activeRules.add(add);
    }

    const verifiedCk = this.currentChecksum();
    if (verifiedCk !== delta.newChecksum) {
      throw new Error('Post-apply checksum mismatch');
    }

    return this.activeRules.size;
  }

  currentChecksum(): string {
    return PacDiffSynchronizer.computeChecksumForSet(this.activeRules);
  }

  containsRule(domain: string): boolean {
    return this.activeRules.has(domain.trim().toLowerCase());
  }

  totalRules(): number {
    return this.activeRules.size;
  }

  static computeChecksumForSet(set: Set<string>): string {
    const sorted = Array.from(set).sort();
    const payload = sorted.map((s) => s + '\n').join('');
    return sha256Sync(payload);
  }
}
