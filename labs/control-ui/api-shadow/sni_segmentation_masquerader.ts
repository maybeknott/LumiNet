export const SegmentationStrategy = {
  SniBorderSplit: 'SniBorderSplit',
  MidSniSplit: 'MidSniSplit',
  RandomSplit: 'RandomSplit',
} as const;
export type SegmentationStrategy = (typeof SegmentationStrategy)[keyof typeof SegmentationStrategy];

export class SniSegmentationMasquerader {
  public strategy: SegmentationStrategy;
  public minChunkSize: number;
  public maxChunkSize: number;

  constructor(
    strategy: SegmentationStrategy = SegmentationStrategy.MidSniSplit,
    minChunkSize: number = 10,
    maxChunkSize: number = 50,
  ) {
    this.strategy = strategy;
    this.minChunkSize = Math.max(2, minChunkSize);
    this.maxChunkSize = Math.max(minChunkSize + 1, maxChunkSize);
  }

  extractSni(data: Uint8Array): { sni: string; start: number; end: number } | null {
    if (data.length < 43 || data[0] !== 0x16) {
      return null;
    }

    let idx = 43;
    if (idx >= data.length) return null;

    // Skip session ID
    const sessionIdLen = data[idx]!;
    idx += 1 + sessionIdLen;
    if (idx + 2 >= data.length) return null;

    // Skip cipher suites
    const cipherLen = (data[idx]! << 8) | data[idx + 1]!;
    idx += 2 + cipherLen;
    if (idx + 1 >= data.length) return null;

    // Skip compression methods
    const compLen = data[idx]!;
    idx += 1 + compLen;
    if (idx + 2 >= data.length) return null;

    // Extensions length
    const extLen = (data[idx]! << 8) | data[idx + 1]!;
    idx += 2;
    const extEnd = Math.min(idx + extLen, data.length);

    while (idx + 4 <= extEnd) {
      const extType = (data[idx]! << 8) | data[idx + 1]!;
      const extSize = (data[idx + 2]! << 8) | data[idx + 3]!;
      idx += 4;

      if (extType === 0) {
        if (idx + extSize <= extEnd && extSize >= 5) {
          const sniNameLen = (data[idx + 3]! << 8) | data[idx + 4]!;
          const sniStart = idx + 5;
          const sniEnd = sniStart + sniNameLen;
          if (sniEnd <= idx + extSize && sniEnd <= data.length) {
            const sni = new TextDecoder().decode(data.subarray(sniStart, sniEnd));
            return { sni, start: sniStart, end: sniEnd };
          }
        }
      }
      idx += extSize;
    }

    return null;
  }

  segmentStream(data: Uint8Array, seed: number = 42): Uint8Array[] {
    if (data.length === 0) return [];

    const extracted = this.extractSni(data);
    if (extracted) {
      const { start, end } = extracted;
      if (this.strategy === SegmentationStrategy.SniBorderSplit) {
        const chunks: Uint8Array[] = [];
        if (start > 0) chunks.push(data.subarray(0, start));
        chunks.push(data.subarray(start, end));
        if (end < data.length) chunks.push(data.subarray(end));
        return chunks;
      } else if (this.strategy === SegmentationStrategy.MidSniSplit) {
        const mid = start + Math.floor((end - start) / 2);
        return [data.subarray(0, mid), data.subarray(mid)];
      }
    }

    // Pseudo-random split using LCG
    let rngState = seed >>> 0;
    const nextRng = () => {
      rngState = (Math.imul(1664525, rngState) + 1013904223) >>> 0;
      return rngState;
    };

    const chunks: Uint8Array[] = [];
    let curr = 0;
    const range = Math.max(1, this.maxChunkSize - this.minChunkSize);

    while (curr < data.length) {
      const remaining = data.length - curr;
      let step: number;
      if (remaining <= this.minChunkSize) {
        step = remaining;
      } else {
        step = Math.min(this.minChunkSize + (nextRng() % range), remaining);
      }
      chunks.push(data.subarray(curr, curr + step));
      curr += step;
    }

    return chunks;
  }
}
