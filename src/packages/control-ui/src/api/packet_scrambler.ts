export const ScrambleAction = {
  Accept: 'accept',
  AlterTTL: 'alter_ttl',
  MarkPacket: 'mark_packet',
} as const;
export type ScrambleAction = (typeof ScrambleAction)[keyof typeof ScrambleAction];

export class PacketScrambler {
  public ttlHopLimit = 64;
  private shortcuts: Map<string, { createdAt: number; ttlMs: number }> = new Map();
  public totalScrambled = 0;
  public queueNum: number;
  public defaultMark: number;
  constructor(queueNum: number, defaultMark: number) {
    this.queueNum = queueNum;
    this.defaultMark = defaultMark;
  }

  addShortcut(dest: string, ttlMs: number): void {
    this.shortcuts.set(dest, { createdAt: Date.now(), ttlMs });
  }

  hasActiveShortcut(dest: string): boolean {
    const entry = this.shortcuts.get(dest);
    if (!entry) return false;
    if (Date.now() - entry.createdAt < entry.ttlMs) {
      return true;
    }
    return false;
  }

  processIPPacket(dest: string, packet: Uint8Array): ScrambleAction {
    if (this.hasActiveShortcut(dest)) {
      return ScrambleAction.MarkPacket;
    }

    this.totalScrambled++;
    if (packet.length < 40) return ScrambleAction.Accept;

    // IPv4 check
    if (packet[0]! >> 4 === 4) {
      const proto = packet[9];
      if (proto === 6) {
        // TCP
        const ihl = (packet[0]! & 0x0f) * 4;
        if (ihl + 13 < packet.length) {
          const flags = packet[ihl + 13]!;
          if ((flags & 0x12) === 0x12) {
            // SYN+ACK
            packet[8] = this.ttlHopLimit;
            return ScrambleAction.AlterTTL;
          }
        }
      }
    }
    return ScrambleAction.Accept;
  }
}
