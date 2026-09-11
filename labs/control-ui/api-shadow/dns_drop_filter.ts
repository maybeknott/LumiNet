export class DnsDropFilter {
  public droppedCount = 0;
  public passedCount = 0;

  inspectPacket(ipId: number, fragOff: number, srcPort: number, dnsPayload: Uint8Array): boolean {
    if (srcPort !== 53) {
      this.passedCount++;
      return true;
    }
    if (ipId === 0) {
      this.droppedCount++;
      return false;
    }
    if (fragOff === 0x0040) {
      this.droppedCount++;
      return false;
    }
    if (dnsPayload.length < 12) {
      this.passedCount++;
      return true;
    }

    const answerRRs = (dnsPayload[6]! << 8) | dnsPayload[7]!;
    const authRRs = (dnsPayload[8]! << 8) | dnsPayload[9]!;
    const aaBit = (dnsPayload[2]! & 0x04) !== 0;

    if (answerRRs === 1 && authRRs === 0 && aaBit) {
      this.droppedCount++;
      return false;
    }

    this.passedCount++;
    return true;
  }
}
