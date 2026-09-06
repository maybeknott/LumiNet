export const FlowProtocol = {
  Unknown: 'unknown',
  TLS: 'tls',
  HTTP: 'http',
  SSH: 'ssh',
  WireGuard: 'wireguard',
  QUIC: 'quic',
} as const;
export type FlowProtocol = (typeof FlowProtocol)[keyof typeof FlowProtocol];

export interface FlowRecord {
  flowId: number;
  src: string;
  dst: string;
  protocol: FlowProtocol;
  packetsSent: number;
  packetsRecv: number;
  bytesSent: number;
  bytesRecv: number;
  retransmissions: number;
}

export class FlowAnalyzerEngine {
  private flows: Map<number, FlowRecord> = new Map();
  private nextFlowId = 1;

  static inspectPayload(payload: Uint8Array): FlowProtocol {
    if (payload.length === 0) return FlowProtocol.Unknown;
    if (payload.length >= 3 && payload[0] === 0x16 && payload[1] === 0x03) {
      return FlowProtocol.TLS;
    }
    const head = new TextDecoder().decode(payload.slice(0, 8));
    if (head.startsWith('GET ') || head.startsWith('POST ') || head.startsWith('HTTP')) {
      return FlowProtocol.HTTP;
    }
    if (head.startsWith('SSH-')) {
      return FlowProtocol.SSH;
    }
    return FlowProtocol.Unknown;
  }

  registerFlow(src: string, dst: string, payload: Uint8Array): number {
    const fid = this.nextFlowId++;
    const proto = FlowAnalyzerEngine.inspectPayload(payload);
    this.flows.set(fid, {
      flowId: fid,
      src,
      dst,
      protocol: proto,
      packetsSent: 1,
      packetsRecv: 0,
      bytesSent: payload.length,
      bytesRecv: 0,
      retransmissions: 0,
    });
    return fid;
  }

  recordPacket(flowId: number, bytes: number, isEgress: boolean, isRetransmission: boolean): void {
    const f = this.flows.get(flowId);
    if (!f) return;
    if (isEgress) {
      f.packetsSent++;
      f.bytesSent += bytes;
      if (isRetransmission) f.retransmissions++;
    } else {
      f.packetsRecv++;
      f.bytesRecv += bytes;
    }
  }

  getFlow(flowId: number): FlowRecord | undefined {
    return this.flows.get(flowId);
  }

  detectAnomalies(maxRetransmissionRatio: number): number[] {
    const anomalies: number[] = [];
    for (const [id, f] of this.flows.entries()) {
      if (f.packetsSent > 0) {
        const ratio = (f.retransmissions / f.packetsSent) * 100.0;
        if (ratio > maxRetransmissionRatio) {
          anomalies.push(id);
        }
      }
    }
    return anomalies;
  }
}
