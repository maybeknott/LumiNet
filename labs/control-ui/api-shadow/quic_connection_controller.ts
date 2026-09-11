export const QuicConnectionState = {
  Idle: 'Idle',
  Initial: 'Initial',
  Handshaking: 'Handshaking',
  Established: 'Established',
  Closing: 'Closing',
  Closed: 'Closed',
} as const;
export type QuicConnectionState = (typeof QuicConnectionState)[keyof typeof QuicConnectionState];

export interface QuicConnectionMetrics {
  state: QuicConnectionState;
  smoothedRttMs: number;
  rttvarMs: number;
  minRttMs: number;
  congestionWindowBytes: number;
  bytesInFlight: number;
  lostPacketsCount: number;
}

interface SentPacketRecord {
  packetNumber: number;
  sizeBytes: number;
  timeSentMs: number;
}

export class QuicConnectionController {
  private state: QuicConnectionState = QuicConnectionState.Idle;
  private smoothedRttMs: number = 100;
  private rttvarMs: number = 50;
  private minRttMs: number = Number.MAX_SAFE_INTEGER;
  private cwndBytes: number;
  private bytesInFlight: number = 0;
  private lostPacketsCount: number = 0;
  private ssthreshBytes: number = Number.MAX_SAFE_INTEGER;
  private sentPackets: Map<number, SentPacketRecord> = new Map();

  constructor(initialWindowBytes: number = 20000) {
    this.cwndBytes = Math.max(14720, initialWindowBytes);
  }

  setState(state: QuicConnectionState): void {
    this.state = state;
  }

  canSend(packetBytes: number): boolean {
    return (
      this.state === QuicConnectionState.Established &&
      this.bytesInFlight + packetBytes <= this.cwndBytes
    );
  }

  onPacketSent(packetNumber: number, sizeBytes: number, timeSentMs: number): void {
    this.bytesInFlight += sizeBytes;
    this.sentPackets.set(packetNumber, {
      packetNumber,
      sizeBytes,
      timeSentMs,
    });
  }

  onAckReceived(ackedPacketNumber: number, nowMs: number): void {
    const record = this.sentPackets.get(ackedPacketNumber);
    if (!record) return;

    this.sentPackets.delete(ackedPacketNumber);
    this.bytesInFlight = Math.max(0, this.bytesInFlight - record.sizeBytes);

    if (nowMs >= record.timeSentMs) {
      const sampleRtt = nowMs - record.timeSentMs;
      this.updateRtt(sampleRtt);
    }

    // Congestion window expansion
    if (this.cwndBytes < this.ssthreshBytes) {
      this.cwndBytes += record.sizeBytes;
    } else {
      const increment = Math.floor((1472 * 1472) / Math.max(1, this.cwndBytes));
      this.cwndBytes += Math.max(1, increment);
    }
  }

  onPacketLoss(lostPacketNumber: number): void {
    const record = this.sentPackets.get(lostPacketNumber);
    if (!record) return;

    this.sentPackets.delete(lostPacketNumber);
    this.bytesInFlight = Math.max(0, this.bytesInFlight - record.sizeBytes);
    this.lostPacketsCount += 1;

    // Multiplicative decrease
    this.ssthreshBytes = Math.max(14720, Math.floor(this.cwndBytes / 2));
    this.cwndBytes = this.ssthreshBytes;
  }

  calculatePtoMs(): number {
    return this.smoothedRttMs + Math.max(10, 4 * this.rttvarMs);
  }

  getMetrics(): QuicConnectionMetrics {
    return {
      state: this.state,
      smoothedRttMs: this.smoothedRttMs,
      rttvarMs: this.rttvarMs,
      minRttMs: this.minRttMs === Number.MAX_SAFE_INTEGER ? 0 : this.minRttMs,
      congestionWindowBytes: this.cwndBytes,
      bytesInFlight: this.bytesInFlight,
      lostPacketsCount: this.lostPacketsCount,
    };
  }

  private updateRtt(sampleRtt: number): void {
    if (this.minRttMs === Number.MAX_SAFE_INTEGER) {
      this.minRttMs = sampleRtt;
      this.smoothedRttMs = sampleRtt;
      this.rttvarMs = Math.floor(sampleRtt / 2);
    } else {
      this.minRttMs = Math.min(this.minRttMs, sampleRtt);
      const diff = Math.abs(sampleRtt - this.smoothedRttMs);
      this.rttvarMs = Math.floor((3 * this.rttvarMs + diff) / 4);
      this.smoothedRttMs = Math.floor((7 * this.smoothedRttMs + sampleRtt) / 8);
    }
  }
}
