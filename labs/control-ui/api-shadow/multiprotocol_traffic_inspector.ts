// Control UI TypeScript: Multiprotocol Traffic Inspector API

export type ProtocolType = 'unknown' | 'rdp' | 'ssh' | 'tls' | 'http' | 'websocket';
export type InspectionVerdict = 'permitted' | 'denied' | 'needs_more_data';

export interface InspectorPolicy {
  allowRdp: boolean;
  allowSsh: boolean;
  allowTls: boolean;
  allowHttp: boolean;
  enforceSni: boolean;
}

export class MultiprotocolTrafficInspector {
  public policy: InspectorPolicy;
  public inspectedCount: number = 0;

  constructor(policy?: Partial<InspectorPolicy>) {
    this.policy = {
      allowRdp: policy?.allowRdp ?? true,
      allowSsh: policy?.allowSsh ?? true,
      allowTls: policy?.allowTls ?? true,
      allowHttp: policy?.allowHttp ?? true,
      enforceSni: policy?.enforceSni ?? false,
    };
  }

  public inspectStream(data: Uint8Array): {
    protocol: ProtocolType;
    verdict: InspectionVerdict;
    metadata: string | null;
  } {
    this.inspectedCount++;
    if (data.length === 0) {
      return {
        protocol: 'unknown',
        verdict: 'needs_more_data',
        metadata: null,
      };
    }

    const str = new TextDecoder('utf-8', { fatal: false }).decode(data);

    // SSH check
    if (str.startsWith('SSH-')) {
      const banner = str.split('\r\n')[0] || '';
      return {
        protocol: 'ssh',
        verdict: this.policy.allowSsh ? 'permitted' : 'denied',
        metadata: banner,
      };
    }

    // TLS Handshake check
    if (data.length >= 5 && data[0] === 0x16 && data[1] === 0x03) {
      const sni = this.extractSni(data);
      if (this.policy.enforceSni && !sni) {
        return { protocol: 'tls', verdict: 'denied', metadata: null };
      }
      return {
        protocol: 'tls',
        verdict: this.policy.allowTls ? 'permitted' : 'denied',
        metadata: sni,
      };
    }

    // RDP check
    if (data.length >= 4 && data[0] === 0x03 && data[1] === 0x00) {
      return {
        protocol: 'rdp',
        verdict: this.policy.allowRdp ? 'permitted' : 'denied',
        metadata: 'TPKT',
      };
    }

    // HTTP / WebSocket check
    if (
      str.startsWith('GET ') ||
      str.startsWith('POST ') ||
      str.startsWith('CONNECT ') ||
      str.startsWith('HEAD ')
    ) {
      const isWs = str.toLowerCase().includes('upgrade: websocket');
      const proto = isWs ? 'websocket' : 'http';
      return {
        protocol: proto,
        verdict: this.policy.allowHttp ? 'permitted' : 'denied',
        metadata: null,
      };
    }

    if (data.length < 8) {
      return {
        protocol: 'unknown',
        verdict: 'needs_more_data',
        metadata: null,
      };
    }
    return { protocol: 'unknown', verdict: 'denied', metadata: null };
  }

  private extractSni(data: Uint8Array): string | null {
    if (data.length < 43 || data[5] !== 0x01) return null;
    let cursor = 43;
    if (cursor >= data.length) return null;

    const sessLen = data[cursor]!;
    cursor += 1 + sessLen;
    if (cursor + 2 > data.length) return null;

    const view = new DataView(data.buffer, data.byteOffset, data.byteLength);
    const cipherLen = view.getUint16(cursor);
    cursor += 2 + cipherLen;
    if (cursor + 1 > data.length) return null;

    const compLen = data[cursor]!;
    cursor += 1 + compLen;
    if (cursor + 2 > data.length) return null;

    const extLen = view.getUint16(cursor);
    cursor += 2;
    const extEnd = Math.min(cursor + extLen, data.length);

    while (cursor + 4 <= extEnd) {
      const extType = view.getUint16(cursor);
      const extDataLen = view.getUint16(cursor + 2);
      cursor += 4;

      if (extType === 0x0000 && cursor + 5 <= extEnd) {
        const nameType = data[cursor + 2];
        const nameLen = view.getUint16(cursor + 3);
        if (nameType === 0 && cursor + 5 + nameLen <= extEnd) {
          const nameBytes = data.slice(cursor + 5, cursor + 5 + nameLen);
          return new TextDecoder().decode(nameBytes);
        }
      }
      cursor += extDataLen;
    }
    return null;
  }
}
