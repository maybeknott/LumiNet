export type AnomalyType = 'tcp_rst_injection' | 'dns_pollution' | 'udp_blackhole' | 'sni_reset';

export interface AnomalySignature {
  type: AnomalyType;
  confidence: number;
  details: string;
}

export class CensorshipProber {
  probeTcpRst(rstReceived: boolean, rstTtl: number, synAckTtl: number): AnomalySignature | null {
    if (!rstReceived) return null;
    const diff = Math.abs(rstTtl - synAckTtl);
    const confidence = diff >= 5 ? 0.95 : 0.65;
    return {
      type: 'tcp_rst_injection',
      confidence,
      details: `TCP RST injection detected with TTL delta: ${diff}`,
    };
  }

  probeDnsPollution(domain: string, ips: string[]): AnomalySignature | null {
    for (const ip of ips) {
      if (ip.startsWith('127.') || ip.startsWith('10.') || ip.startsWith('192.168.')) {
        return {
          type: 'dns_pollution',
          confidence: 0.95,
          details: `Domain ${domain} resolved to reserved address ${ip}`,
        };
      }
    }
    return null;
  }

  probeUdpDrop(sent: number, recvd: number): AnomalySignature | null {
    if (sent < 5) return null;
    const loss = (sent - recvd) / sent;
    if (loss >= 0.90) {
      return {
        type: 'udp_blackhole',
        confidence: 0.92,
        details: `Severe UDP blackholing: ${Math.round(loss * 100)}% packet loss`,
      };
    }
    return null;
  }
}
