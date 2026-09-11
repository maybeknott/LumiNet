export interface RendezvousSession {
  token: string;
  initiator: string;
  responder?: string;
  connected: boolean;
}

export class RendezvousBridgeManager {
  private sessions = new Map<string, RendezvousSession>();

  register(initiator: string): string {
    const token = `rdv-${Date.now()}-${Math.floor(Math.random() * 10000)}`;
    this.sessions.set(token, { token, initiator, connected: false });
    return token;
  }

  connect(token: string, responder: string): RendezvousSession {
    const sess = this.sessions.get(token);
    if (!sess) throw new Error("session token not found");
    if (sess.connected) throw new Error("session already connected");
    sess.responder = responder;
    sess.connected = true;
    return sess;
  }

  getSession(token: string): RendezvousSession | undefined {
    return this.sessions.get(token);
  }
}
