export interface UiReverseSession {
  sessionId: number;
  remoteAddr: string;
  targetAddr: string;
  bytesIn: number;
  bytesOut: number;
  isConnected: boolean;
}

export class ReverseTunnelRelay {
  private sessions: Map<number, UiReverseSession> = new Map();
  private nextId = 1;
  private maxSessions: number;
  constructor(maxSessions: number = 100) {
    this.maxSessions = maxSessions;
  }

  openSession(remoteAddr: string, targetAddr: string): number | null {
    if (this.sessions.size >= this.maxSessions) return null;
    const id = this.nextId++;
    this.sessions.set(id, {
      sessionId: id,
      remoteAddr,
      targetAddr,
      bytesIn: 0,
      bytesOut: 0,
      isConnected: true,
    });
    return id;
  }

  recordTraffic(sessionId: number, inBytes: number, outBytes: number): boolean {
    const s = this.sessions.get(sessionId);
    if (!s || !s.isConnected) return false;
    s.bytesIn += inBytes;
    s.bytesOut += outBytes;
    return true;
  }

  closeSession(sessionId: number): boolean {
    const s = this.sessions.get(sessionId);
    if (!s) return false;
    s.isConnected = false;
    this.sessions.delete(sessionId);
    return true;
  }

  activeSessions(): number {
    return this.sessions.size;
  }
}
