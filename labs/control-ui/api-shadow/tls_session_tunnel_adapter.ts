export interface UiSessionTicket {
  ticketId: string;
  serverName: string;
  masterSecret: Uint8Array;
  maxEarlyData: number;
  expiresAtSecs: number;
}

export class TlsSessionTunnelAdapter {
  private ticketCache: Map<string, UiSessionTicket> = new Map();

  storeTicket(ticket: UiSessionTicket): void {
    this.ticketCache.set(ticket.serverName, ticket);
  }

  retrieveTicket(serverName: string, nowSecs: number): UiSessionTicket | null {
    const ticket = this.ticketCache.get(serverName);
    if (!ticket) return null;
    if (nowSecs > ticket.expiresAtSecs) return null;
    return ticket;
  }

  frameEarlyData(ticketId: string, payload: Uint8Array): Uint8Array {
    const encoder = new TextEncoder();
    const tBytes = encoder.encode(ticketId);
    if (tBytes.length > 255) {
      throw new Error('Ticket ID exceeds 255 bytes');
    }

    const frame = new Uint8Array(1 + tBytes.length + 2 + payload.length);
    frame[0] = tBytes.length;
    frame.set(tBytes, 1);
    const pLen = payload.length;
    frame[1 + tBytes.length] = (pLen >> 8) & 0xff;
    frame[2 + tBytes.length] = pLen & 0xff;
    frame.set(payload, 3 + tBytes.length);
    return frame;
  }

  unframeEarlyData(data: Uint8Array): { ticketId: string; payload: Uint8Array } | null {
    if (data.length < 3) return null;
    const tLen = data[0]!;
    if (data.length < 1 + tLen + 2) return null;

    const decoder = new TextDecoder();
    const ticketId = decoder.decode(data.slice(1, 1 + tLen));
    const pLen = (data[1 + tLen]! << 8) | data[2 + tLen]!;
    const start = 3 + tLen;
    if (data.length < start + pLen) return null;

    const payload = data.slice(start, start + pLen);
    return { ticketId, payload };
  }
}
