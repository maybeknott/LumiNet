export interface DnsTunnelFrame {
  sessionId: number;
  sequence: number;
  isFinal: boolean;
  payload: Uint8Array;
}

export class DnsTunnelCodec {
  public static encodeToQuery(frame: DnsTunnelFrame, domainSuffix: string): string {
    const raw = new Uint8Array(5 + frame.payload.length);
    raw[0] = (frame.sessionId >> 8) & 0xff;
    raw[1] = frame.sessionId & 0xff;
    raw[2] = (frame.sequence >> 8) & 0xff;
    raw[3] = frame.sequence & 0xff;
    raw[4] = frame.isFinal ? 1 : 0;
    raw.set(frame.payload, 5);

    const hex = Array.from(raw).map(b => b.toString(16).padStart(2, '0')).join('');
    return `${hex}.${domainSuffix}`;
  }

  public static decodeFromQuery(query: string, domainSuffix: string): DnsTunnelFrame | null {
    if (!query.endsWith(domainSuffix)) return null;
    let trimmed = query.slice(0, query.length - domainSuffix.length);
    if (trimmed.endsWith('.')) trimmed = trimmed.slice(0, -1);
    const label = trimmed.split('.')[0] ?? '';
    if (label.length < 10 || label.length % 2 !== 0) return null;

    const raw = new Uint8Array(label.length / 2);
    for (let i = 0; i < raw.length; i++) {
      raw[i] = parseInt(label.slice(i * 2, i * 2 + 2), 16);
    }

    const sessionId = ((raw[0] ?? 0) << 8) | (raw[1] ?? 0);
    const sequence = ((raw[2] ?? 0) << 8) | (raw[3] ?? 0);
    const isFinal = (raw[4] ?? 0) === 1;
    const payload = raw.slice(5);

    return { sessionId, sequence, isFinal, payload };
  }
}
