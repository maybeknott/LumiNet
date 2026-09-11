/**
 * TCP Handshake Flow Latency & RTT Tracker API.
 *
 * Ported and unified from `flowlat-master`.
 * Provides 4-tuple symmetric FNV-1a flow hashing, in-flight TCP handshake tracking,
 * round-trip time (RTT) calculation, jitter estimation, and percentile analysis.
 */

const FNV_OFFSET_BASIS: bigint = 14695981039346656037n;
const FNV_PRIME: bigint = 1099511628211n;

/**
 * Computes 64-bit FNV-1a hash over raw byte buffer using BigInt.
 */
export function fnv1aHash(data: Uint8Array): bigint {
  let h = FNV_OFFSET_BASIS;
  for (let i = 0; i < data.length; i++) {
    h ^= BigInt(data[i]!);
    h = (h * FNV_PRIME) & 0xffffffffffffffffn;
  }
  return h;
}

/**
 * Helper to encode IPv4 string into 16-byte IPv4-mapped array.
 */
function ipTo16Bytes(ipStr: string): Uint8Array {
  const buf = new Uint8Array(16);
  if (ipStr.includes(':')) {
    // For IPv6 strings, fill simple hash or parse hex segments
    const parts = ipStr.split(':').filter(Boolean);
    for (let i = 0; i < Math.min(parts.length, 8); i++) {
      const val = parseInt(parts[i]!, 16) || 0;
      buf[i * 2] = (val >> 8) & 0xff;
      buf[i * 2 + 1] = val & 0xff;
    }
    return buf;
  }

  // IPv4-mapped (::ffff:a.b.c.d)
  buf[10] = 0xff;
  buf[11] = 0xff;
  const octets = ipStr.split('.').map((s) => parseInt(s, 10) || 0);
  for (let i = 0; i < 4; i++) {
    buf[12 + i] = octets[i]! & 0xff;
  }
  return buf;
}

/**
 * Computes symmetrical 4-tuple flow hash where forward and reverse packets
 * map to the identical bucket.
 */
export function computeFlowHash(
  srcIp: string,
  srcPort: number,
  dstIp: string,
  dstPort: number,
): bigint {
  const src16 = ipTo16Bytes(srcIp);
  const dst16 = ipTo16Bytes(dstIp);

  const bufSrc = new Uint8Array(18);
  bufSrc.set(src16, 0);
  bufSrc[16] = (srcPort >> 8) & 0xff;
  bufSrc[17] = srcPort & 0xff;

  const bufDst = new Uint8Array(18);
  bufDst.set(dst16, 0);
  bufDst[16] = (dstPort >> 8) & 0xff;
  bufDst[17] = dstPort & 0xff;

  const hSrc = fnv1aHash(bufSrc);
  const hDst = fnv1aHash(bufDst);

  return ((hSrc + hDst) * FNV_PRIME) & 0xffffffffffffffffn;
}

export interface FlowLatencyStats {
  sampleCount: number;
  minRttMs?: number;
  maxRttMs?: number;
  totalRttMs: number;
  averageRttMs?: number;
  jitterMs?: number;
  history: number[];
}

export class FlowLatencyTracker {
  private synTable = new Map<string, number>();
  private stats: FlowLatencyStats = {
    sampleCount: 0,
    totalRttMs: 0,
    history: [],
  };

  /**
   * Registers in-flight SYN packet timestamp in milliseconds.
   */
  public onSyn(
    srcIp: string,
    srcPort: number,
    dstIp: string,
    dstPort: number,
    timestampMs: number,
  ): void {
    const key = computeFlowHash(srcIp, srcPort, dstIp, dstPort).toString();
    this.synTable.set(key, timestampMs);
  }

  /**
   * Processes matching SYN-ACK packet and returns computed RTT in milliseconds.
   */
  public onSynAck(
    srcIp: string,
    srcPort: number,
    dstIp: string,
    dstPort: number,
    timestampMs: number,
  ): number | undefined {
    const key = computeFlowHash(srcIp, srcPort, dstIp, dstPort).toString();
    const synTs = this.synTable.get(key);
    if (synTs === undefined) {
      return undefined;
    }
    this.synTable.delete(key);

    if (timestampMs < synTs) {
      return undefined;
    }

    const rtt = timestampMs - synTs;
    this.recordSample(rtt);
    return rtt;
  }

  private recordSample(rtt: number): void {
    this.stats.sampleCount++;
    this.stats.totalRttMs += rtt;
    this.stats.history.push(rtt);
    if (this.stats.history.length > 500) {
      this.stats.history.shift();
    }

    this.stats.minRttMs =
      this.stats.minRttMs !== undefined ? Math.min(this.stats.minRttMs, rtt) : rtt;
    this.stats.maxRttMs =
      this.stats.maxRttMs !== undefined ? Math.max(this.stats.maxRttMs, rtt) : rtt;
    this.stats.averageRttMs = this.stats.totalRttMs / this.stats.sampleCount;

    // Calculate jitter as mean absolute difference between sequential samples
    if (this.stats.history.length >= 2) {
      let diffSum = 0;
      for (let i = 1; i < this.stats.history.length; i++) {
        diffSum += Math.abs(this.stats.history[i]! - this.stats.history[i - 1]!);
      }
      this.stats.jitterMs = diffSum / (this.stats.history.length - 1);
    }
  }

  /**
   * Prunes orphaned handshakes older than maxAgeMs.
   */
  public pruneStale(nowMs: number, maxAgeMs: number): number {
    let pruned = 0;
    for (const [key, ts] of this.synTable.entries()) {
      if (nowMs - ts > maxAgeMs) {
        this.synTable.delete(key);
        pruned++;
      }
    }
    return pruned;
  }

  public pendingCount(): number {
    return this.synTable.size;
  }

  public getStats(): FlowLatencyStats {
    return { ...this.stats, history: [...this.stats.history] };
  }

  /**
   * Computes p50, p90, and p99 percentiles from recent history.
   */
  public computePercentiles(): { p50: number; p90: number; p99: number } {
    if (this.stats.history.length === 0) {
      return { p50: 0, p90: 0, p99: 0 };
    }
    const sorted = [...this.stats.history].sort((a, b) => a - b);
    const getP = (p: number) => {
      const idx = Math.min(Math.floor((p / 100) * sorted.length), sorted.length - 1);
      return sorted[idx]!;
    };
    return {
      p50: getP(50),
      p90: getP(90),
      p99: getP(99),
    };
  }
}
