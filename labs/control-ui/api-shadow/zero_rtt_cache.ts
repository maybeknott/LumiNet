/**
 * QUIC / TLS 1.3 0-RTT Session Ticket Cache
 */
export interface SessionTicket {
  serverName: string;
  ticket: Uint8Array;
  alpn: string;
  expiresAtUnix: number;
}

export class ZeroRttSessionCache {
  private tickets: Map<string, SessionTicket> = new Map();
  private consumedNonces: Set<string> = new Set();

  storeTicket(serverName: string, ticket: Uint8Array, alpn: string, nowUnix: number, ttlSecs: number): void {
    const key = serverName.toLowerCase();
    this.tickets.set(key, {
      serverName,
      ticket: new Uint8Array(ticket),
      alpn,
      expiresAtUnix: nowUnix + ttlSecs,
    });
  }

  getValidTicket(serverName: string, nowUnix: number): SessionTicket | null {
    const key = serverName.toLowerCase();
    const t = this.tickets.get(key);
    if (!t) return null;
    if (t.expiresAtUnix > nowUnix) {
      return t;
    }
    this.tickets.delete(key);
    return null;
  }

  checkAndConsumeNonce(nonce: Uint8Array): boolean {
    const key = Array.from(nonce).map((b) => b.toString(16).padStart(2, '0')).join('');
    if (this.consumedNonces.has(key)) return false;
    this.consumedNonces.add(key);
    return true;
  }
}
