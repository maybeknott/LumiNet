/**
 * Multipath Packet Deduplication Buffer
 */
export class MultipathDedupBuffer {
  private seenHistory: Set<number> = new Set();
  private reorderQueue: Map<number, Uint8Array> = new Map();
  public expectedSeq: number;
  public maxHistorySize: number;
  constructor(expectedSeq: number = 1, maxHistorySize: number = 128) {
    this.expectedSeq = expectedSeq;
    this.maxHistorySize = maxHistorySize;
  }

  ingest(seq: number, data: Uint8Array): Uint8Array[] {
    if (seq < this.expectedSeq || this.seenHistory.has(seq) || this.reorderQueue.has(seq)) {
      return [];
    }

    this.seenHistory.add(seq);
    if (this.seenHistory.size > this.maxHistorySize) {
      const min = Math.min(...this.seenHistory);
      this.seenHistory.delete(min);
    }

    this.reorderQueue.set(seq, data);

    const ready: Uint8Array[] = [];
    while (this.reorderQueue.has(this.expectedSeq)) {
      ready.push(this.reorderQueue.get(this.expectedSeq)!);
      this.reorderQueue.delete(this.expectedSeq);
      this.expectedSeq++;
    }

    return ready;
  }
}
